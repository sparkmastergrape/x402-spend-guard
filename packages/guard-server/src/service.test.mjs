import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rlusd } from "spend-gate";

import { createGuardService, mandateFromJson, grantFromJson } from "./service.js";
import { serviceFromEnv } from "./config.js";
import { fixture, signedMandate, signGrant, agent, approver, AGENT_KEY, PRICE } from "./test-support.mjs";

test("pay: an allowed payment settles and returns the resource body", async (t) => {
  const { service, merchant, url } = await fixture();
  t.after(() => merchant.close());

  const r = await service.pay({ url });
  assert.equal(r.outcome, "paid");
  assert.equal(r.amount, PRICE.toString(), "bigints cross the boundary as decimal strings");
  assert.ok(r.txHash);
  assert.equal(r.status, 200);
  assert.match(r.body, /"price":"mock"/);
  assert.equal(merchant.stats().redemptions.length, 1);
});

test("pay: a redirected payee is refused, and nothing is signed", async (t) => {
  const { service, merchant, url } = await fixture({
    policy: { onUnknownMerchant: "DENY" },
    merchantFaults: { payTo: "0x000000000000000000000000000000000000dEaD" },
  });
  t.after(() => merchant.close());

  const r = await service.pay({ url });
  assert.equal(r.outcome, "refused");
  assert.equal(r.code, "UNKNOWN_MERCHANT");
  assert.equal(merchant.stats().redemptions.length, 0);
});

test("escalation round trip: the agent stops, a human signs grantToSign, the agent pays once", async (t) => {
  const { service, merchant, url } = await fixture();
  t.after(() => merchant.close());
  merchant.setFault("amount", rlusd("0.2")); // above maxPerCall

  const stopped = await service.pay({ url });
  assert.equal(stopped.outcome, "requires_confirmation");
  assert.equal(stopped.code, "OVER_PER_CALL");
  assert.equal(stopped.grantToSign.primaryType, "Grant");
  assert.equal(stopped.grantToSign.message.amount, rlusd("0.2").toString());

  const grantSignature = await signGrant(stopped.grantToSign);
  const paid = await service.pay({ url, grant: stopped.grantToSign, grantSignature });
  assert.equal(paid.outcome, "paid", paid.message ?? "");

  const again = await service.pay({ url, grant: stopped.grantToSign, grantSignature });
  assert.notEqual(again.outcome, "paid", "a Grant pays once");
  assert.equal(merchant.stats().redemptions.length, 1);
});

test("a Grant signed by anyone but the approver does not pay", async (t) => {
  const { service, merchant, url } = await fixture();
  t.after(() => merchant.close());
  merchant.setFault("amount", rlusd("0.2"));

  const stopped = await service.pay({ url });
  const forged = await agent.signTypedData(stopped.grantToSign); // the agent approves itself
  const r = await service.pay({ url, grant: stopped.grantToSign, grantSignature: forged });
  assert.notEqual(r.outcome, "paid");
  assert.match(r.grantProblem, /expected/);
  assert.equal(merchant.stats().redemptions.length, 0);
});

test("checkPayment reserves, signs and records nothing", async (t) => {
  const { service, merchant, url } = await fixture();
  t.after(() => merchant.close());

  const c = await service.checkPayment({ url });
  assert.equal(c.outcome, "checked");
  assert.equal(c.verdict.decision, "ALLOW");
  assert.equal(c.amount, PRICE.toString());

  assert.equal(merchant.stats().redemptions.length, 0);
  assert.equal(service.audit().length, 0, "a dry run leaves no audit event");
  assert.equal(service.status().spend.total, "0");
  assert.equal(service.status().spend.pending, 0);
});

test("status and audit report the spend in plain JSON", async (t) => {
  const { service, merchant, url } = await fixture();
  t.after(() => merchant.close());

  await service.pay({ url });
  await service.pay({ url });
  const s = service.status();
  assert.equal(s.spend.total, (PRICE * 2n).toString());
  assert.equal(s.caps.maxPerCall, rlusd("0.05").toString());
  assert.equal(typeof s.mandate, "string");
  const a = service.audit();
  assert.equal(a.length, 2);
  assert.ok(a.every((e) => e.outcome === "paid" && !("response" in e)));
  assert.doesNotThrow(() => JSON.stringify(a));
});

test("only http and https URLs are fetched", async (t) => {
  const { service, merchant } = await fixture();
  t.after(() => merchant.close());
  for (const url of ["file:///etc/passwd", "ftp://x/y", "not a url"])
    await assert.rejects(service.pay({ url }), /URL/);
});

test("a mandate the approver did not sign is refused at startup", async () => {
  const { mandate } = await signedMandate();
  const bad = await agent.signTypedData(mandate);
  await assert.rejects(
    createGuardService({ mandate, mandateSignature: bad, approver: approver.address, signer: agent }),
    /does not verify/,
  );
});

test("mandate and Grant JSON round-trip to the same typed data", async () => {
  const { mandate, json } = await signedMandate();
  const back = mandateFromJson(JSON.stringify(json.mandate));
  assert.deepEqual(back, mandate);
  assert.throws(() => grantFromJson({}), /domain/);
});

test("serviceFromEnv: loads the mandate file, checks the agent key, warns when revocation is off", async (t) => {
  const { json } = await signedMandate();
  const dir = mkdtempSync(join(tmpdir(), "guard-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "mandate.json");
  writeFileSync(file, JSON.stringify(json));

  const warnings = [];
  const env = { GUARD_MANDATE_FILE: file, GUARD_APPROVER: approver.address, AGENT_PRIVATE_KEY: AGENT_KEY };
  const svc = await serviceFromEnv(
    { ...env, GUARD_POLICY: JSON.stringify({ expectedPrice: PRICE.toString() }) },
    { warn: (m) => warnings.push(m) },
  );
  assert.ok(svc.mandateId);
  assert.match(warnings.join("\n"), /revocation is OFF/);

  const wrongKey = "0x" + "22".repeat(32);
  await assert.rejects(serviceFromEnv({ ...env, AGENT_PRIVATE_KEY: wrongKey }, { warn() {} }), /mandate names agent/);
  await assert.rejects(serviceFromEnv({ ...env, GUARD_APPROVER: "" }, { warn() {} }), /GUARD_APPROVER is required/);
});
