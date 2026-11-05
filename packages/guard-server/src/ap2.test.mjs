import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rlusd, network } from "spend-gate";
import { generateEs256Jwk, issueRoot, verifyChain } from "../../spend-gate/src/ap2/sdjwt.js";
import { transactionIdForChallenge } from "spend-gate/ap2";
import { createMockMerchant } from "../../spend-gate/src/payer/mock-merchant.mjs";

import { createAp2GuardService } from "./service.js";
import { serviceFromEnv } from "./config.js";
import { agent, approver, AGENT_KEY, MERCHANT, PRICE, signGrant } from "./test-support.mjs";

function openMandate(agentJwk, { recurrence = true, extra = [] } = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    vct: "mandate.payment.open.1",
    constraints: [
      { type: "payment.amount_range", currency: "USD", max: 5 },
      { type: "payment.budget", currency: "USD", max: 100 },
      ...(recurrence ? [{ type: "payment.agent_recurrence", frequency: "ON_DEMAND" }] : []),
      { type: "payment.allowed_payees", allowed: [{ id: `eip155:${network.CHAIN_ID}:${MERCHANT}`, name: "Data Co" }] },
      ...extra,
    ],
    cnf: { jwk: agentJwk },
    iat: now - 5,
    exp: now + 3600,
  };
}

async function ap2Fixture({ recurrence = true, extra = [], withAgentKey = true, allowUnchecked = [], approverAddress = null } = {}) {
  const user = await generateEs256Jwk();
  const agentKey = await generateEs256Jwk();
  const token = await issueRoot(openMandate(agentKey.publicJwk, { recurrence, extra }), user.privateJwk);
  const merchant = createMockMerchant({ payTo: MERCHANT, agent: agent.address, price: PRICE });
  const { url } = await merchant.listen();
  let lastChallenge = null;
  const service = await createAp2GuardService({
    ap2Token: token,
    userJwk: user.publicJwk,
    agentPrivateJwk: withAgentKey ? agentKey.privateJwk : undefined,
    signer: agent,
    allowUnchecked,
    approver: approverAddress,
    fetchImpl: async (u, init) => {
      const res = await fetch(u, init);
      if (res.status === 402) lastChallenge = res.headers.get("PAYMENT-REQUIRED");
      return res;
    },
  });
  return { service, merchant, url, user, agentKey, token, challenge: () => lastChallenge };
}

test("ap2: a payment under the user's mandate settles and returns a closed Payment Mandate", async (t) => {
  const f = await ap2Fixture();
  t.after(() => f.merchant.close());

  const r = await f.service.pay({ url: f.url });
  assert.equal(r.outcome, "paid", r.message ?? "");
  assert.ok(r.ap2PaymentMandate, r.ap2Problem);

  const origin = new URL(f.url).origin;
  const { hops } = await verifyChain(r.ap2PaymentMandate, f.user.publicJwk, { aud: origin });
  const closed = hops[1].items[0];
  assert.equal(closed.vct, "mandate.payment.1");
  assert.deepEqual(closed.payment_amount, { amount: 1, currency: "USD" }, "0.01 RLUSD is 1 cent");
  assert.equal(closed.payee.id, `eip155:${network.CHAIN_ID}:${MERCHANT}`);
  assert.equal(closed.transaction_id, transactionIdForChallenge(f.challenge()), "bound to the challenge the merchant sent");

  const s = f.service.status();
  assert.equal(s.ap2.paymentsMade, 1);
  assert.equal(s.caps.maxPerCall, rlusd("0.05").toString());
});

test("ap2: the user's amount_range is the per-call cap", async (t) => {
  const f = await ap2Fixture();
  t.after(() => f.merchant.close());
  f.merchant.setFault("amount", rlusd("0.06"));

  const r = await f.service.pay({ url: f.url });
  assert.equal(r.outcome, "requires_confirmation");
  assert.equal(r.code, "OVER_PER_CALL");
  assert.equal(f.merchant.stats().redemptions.length, 0);
});

test("ap2: without agent_recurrence the mandate pays once, even under concurrent calls", async (t) => {
  const f = await ap2Fixture({ recurrence: false });
  t.after(() => f.merchant.close());

  const results = await Promise.all([f.service.pay({ url: f.url }), f.service.pay({ url: f.url }), f.service.pay({ url: f.url })]);
  assert.equal(results.filter((r) => r.outcome === "paid").length, 1);
  assert.ok(results.some((r) => r.code === "AP2_SINGLE_USE"));
  assert.equal(f.merchant.stats().redemptions.length, 1);

  const later = await f.service.pay({ url: f.url });
  assert.equal(later.code, "AP2_SINGLE_USE");
});

test("ap2: without the agent's AP2 key the payment still settles, with no receipt", async (t) => {
  const f = await ap2Fixture({ withAgentKey: false });
  t.after(() => f.merchant.close());
  const r = await f.service.pay({ url: f.url });
  assert.equal(r.outcome, "paid");
  assert.equal(r.ap2PaymentMandate, null);
});

test("ap2: escalations need a configured approver", async (t) => {
  const none = await ap2Fixture();
  t.after(() => none.merchant.close());
  none.merchant.setFault("amount", rlusd("0.06"));
  const stopped = await none.service.pay({ url: none.url });
  const grantSignature = await signGrant(stopped.grantToSign);
  const r = await none.service.pay({ url: none.url, grant: stopped.grantToSign, grantSignature });
  assert.notEqual(r.outcome, "paid");
  assert.match(r.grantProblem, /no approver/);

  const withApprover = await ap2Fixture({ approverAddress: approver.address });
  t.after(() => withApprover.merchant.close());
  withApprover.merchant.setFault("amount", rlusd("0.06"));
  const s2 = await withApprover.service.pay({ url: withApprover.url });
  const ok = await withApprover.service.pay({ url: withApprover.url, grant: s2.grantToSign, grantSignature: await signGrant(s2.grantToSign) });
  assert.equal(ok.outcome, "paid", ok.message ?? "");
});

test("ap2: startup refuses a wrong key, a forged mandate and an unchecked reference", async () => {
  const user = await generateEs256Jwk();
  const agentKey = await generateEs256Jwk();
  const other = await generateEs256Jwk();
  const token = await issueRoot(openMandate(agentKey.publicJwk), user.privateJwk);

  await assert.rejects(
    createAp2GuardService({ ap2Token: token, userJwk: user.publicJwk, agentPrivateJwk: other.privateJwk, signer: agent }),
    /does not match the mandate's cnf/,
  );
  await assert.rejects(createAp2GuardService({ ap2Token: token, userJwk: other.publicJwk, signer: agent }), /does not verify/);

  const withRef = await issueRoot(
    openMandate(agentKey.publicJwk, { extra: [{ type: "payment.reference", conditional_transaction_id: "abc" }] }),
    user.privateJwk,
  );
  await assert.rejects(createAp2GuardService({ ap2Token: withRef, userJwk: user.publicJwk, signer: agent }), /payment.reference/);
  const svc = await createAp2GuardService({
    ap2Token: withRef,
    userJwk: user.publicJwk,
    signer: agent,
    allowUnchecked: ["payment.reference"],
  });
  assert.deepEqual(svc.status().ap2.unchecked, ["payment.reference"]);
});

test("serviceFromEnv: AP2 mode loads from files and says what it does not check", async (t) => {
  const user = await generateEs256Jwk();
  const agentKey = await generateEs256Jwk();
  const token = await issueRoot(
    openMandate(agentKey.publicJwk, { extra: [{ type: "payment.reference", conditional_transaction_id: "abc" }] }),
    user.privateJwk,
  );
  const dir = mkdtempSync(join(tmpdir(), "guard-ap2-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "mandate.sdjwt"), token);
  writeFileSync(join(dir, "agent.jwk"), JSON.stringify(agentKey.privateJwk));

  const warnings = [];
  const svc = await serviceFromEnv(
    {
      GUARD_AP2_MANDATE_FILE: join(dir, "mandate.sdjwt"),
      GUARD_AP2_USER_JWK: JSON.stringify(user.publicJwk),
      GUARD_AP2_AGENT_JWK_FILE: join(dir, "agent.jwk"),
      GUARD_AP2_ALLOW_UNCHECKED: "payment.reference",
      AGENT_PRIVATE_KEY: AGENT_KEY,
    },
    { warn: (m) => warnings.push(m) },
  );
  assert.equal(svc.status().ap2.receipts, true);
  const all = warnings.join("\n");
  assert.match(all, /no revocation check/);
  assert.match(all, /UNCHECKED: payment.reference/);
  assert.match(all, /escalation cannot be approved/);

  await assert.rejects(
    serviceFromEnv({ GUARD_AP2_MANDATE_FILE: join(dir, "mandate.sdjwt"), GUARD_MANDATE_FILE: "x" }, { warn() {} }),
    /not both/,
  );
});
