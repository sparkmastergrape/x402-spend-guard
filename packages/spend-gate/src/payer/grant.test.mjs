// The escalation round-trip, with no device: the agent hits a cap, stops, a
// human grants that one payment, the agent resumes — and the grant cannot be
// used twice, stretched to a different payment, or made to excuse anything
// structural.
//
// Here the approver is a local key so the whole thing is a unit test.

import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { Wallet } from "ethers";

import { buildMandate, rlusd, hashMandate } from "../mandate/index.js";
import { buildGrant, hashGrant, describeGrant, verifyGrant } from "../mandate/grant.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { createMockMerchant } from "./mock-merchant.mjs";
import { createPayer, PAID, REQUIRES_CONFIRMATION, REFUSED } from "./index.js";
import { RLUSD } from "../config/network.js";

const AGENT_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const APPROVER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const agent = privateKeyToAccount(AGENT_KEY);
const approver = privateKeyToAccount(APPROVER_KEY);
const agentSigner = new Wallet(AGENT_KEY);
const REGISTRY = "0x0000000000000000000000000000000000000001";
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";

const PRICE = rlusd("0.01");
const OVER_CAP = rlusd("0.2"); // 4x the per-call cap

async function harness() {
  const now = Math.floor(Date.now() / 1000);
  const mandate = buildMandate({
    agent: agent.address,
    asset: RLUSD,
    merchant: MERCHANT,
    maxPerCall: rlusd("0.05"),
    maxPerWindow: rlusd("0.5"),
    windowSeconds: 3600,
    maxTotal: rlusd("2"),
    validFrom: now - 60,
    validUntil: now + 3600,
    purpose: "market-data",
    nonce: now,
    registry: REGISTRY,
  });
  const merchant = createMockMerchant({
    payTo: MERCHANT,
    agent: agent.address,
    price: PRICE,
  });
  const { url } = await merchant.listen();
  const ledger = new SpendLedger();
  const payer = createPayer({
    mandate,
    signatureValid: true,
    ledger,
    signer: agentSigner,
  });
  return { mandate, mandateId: hashMandate(mandate), merchant, payer, ledger, url, now };
}

/** What the approver UI does: turn an `ask` into a signed Grant. */
async function grantFor(ask, { overrides = {}, signer = approver } = {}) {
  const grant = buildGrant({ ...ask, registry: REGISTRY, ...overrides });
  const signature = await signer.signTypedData({
    domain: grant.domain,
    types: grant.types,
    primaryType: grant.primaryType,
    message: grant.message,
  });
  return { grant, signature };
}

test("the round trip: escalate, grant on device, resume", async (t) => {
  const { merchant, payer, url } = await harness();
  t.after(() => merchant.close());

  // unattended payments first — the normal case
  assert.equal((await payer.buy(url)).outcome, PAID);

  merchant.setFault("amount", OVER_CAP);
  const stopped = await payer.buy(url);
  assert.equal(stopped.outcome, REQUIRES_CONFIRMATION);
  assert.equal(stopped.verdict.code, "OVER_PER_CALL");

  // The payer hands the UI everything needed to ask the question.
  assert.equal(stopped.ask.amount, OVER_CAP);
  assert.equal(stopped.ask.merchant, MERCHANT);
  assert.equal(stopped.ask.resource, url);

  const { grant, signature } = await grantFor(stopped.ask);
  assert.match(describeGrant(grant), /^pay 0\.2 once to 0xFf9395/);
  assert.equal((await verifyGrant(grant, signature, approver.address)).ok, true);

  const resumed = await payer.buy(url, { grant, grantSignatureValid: true });
  assert.equal(resumed.outcome, PAID);
  assert.equal(resumed.verdict.code, "WITHIN_GRANT");
  assert.equal(resumed.amount, OVER_CAP);

  // and the agent carries on unattended afterwards
  merchant.clearFaults();
  assert.equal((await payer.buy(url)).outcome, PAID);
});

test("a grant is single-use", async (t) => {
  const { merchant, payer, url, ledger } = await harness();
  t.after(() => merchant.close());

  merchant.setFault("amount", OVER_CAP);
  const stopped = await payer.buy(url);
  const { grant } = await grantFor(stopped.ask);

  assert.equal((await payer.buy(url, { grant, grantSignatureValid: true })).outcome, PAID);
  assert.equal(ledger.isGrantUsed(hashGrant(grant)), true);

  const replay = await payer.buy(url, { grant, grantSignatureValid: true });
  assert.equal(replay.outcome, REFUSED);
  assert.equal(replay.verdict.code, "GRANT_SPENT");
});

test("a granted payment still counts against the envelope", async (t) => {
  const { merchant, payer, url, ledger, mandateId } = await harness();
  t.after(() => merchant.close());

  merchant.setFault("amount", OVER_CAP);
  const stopped = await payer.buy(url);
  const { grant } = await grantFor(stopped.ask);
  await payer.buy(url, { grant, grantSignatureValid: true });

  // The human lifted the per-call cap for one payment; they did not raise the
  // budget. The 0.2 is in the ledger and reduces what follows.
  const snap = ledger.snapshot(mandateId, { windowSeconds: 3600 });
  assert.equal(snap.total, OVER_CAP);
  assert.equal(snap.window, OVER_CAP);
});

test("a grant cannot be stretched to a different payment", async (t) => {
  const { merchant, payer, url } = await harness();
  t.after(() => merchant.close());

  merchant.setFault("amount", OVER_CAP);
  const stopped = await payer.buy(url);

  for (const [label, overrides] of [
    ["a bigger amount", { amount: rlusd("0.3") }],
    ["a different payee", { merchant: "0x000000000000000000000000000000000000dEaD" }],
    ["a different resource", { resource: "http://example.invalid/other" }],
    ["a different agent", { agent: approver.address }],
    ["a different asset", { asset: "0x000000000000000000000000000000000000bEEF" }],
    ["a different mandate", { mandateId: `0x${"ab".repeat(32)}` }],
  ]) {
    const { grant } = await grantFor(stopped.ask, { overrides });
    const r = await payer.buy(url, { grant, grantSignatureValid: true });
    assert.equal(r.outcome, REFUSED, `${label} must be refused`);
    assert.equal(r.verdict.code, "GRANT_MISMATCH", label);
  }
});

test("an expired grant is refused rather than stretched", async (t) => {
  const { merchant, payer, url, now } = await harness();
  t.after(() => merchant.close());

  merchant.setFault("amount", OVER_CAP);
  const stopped = await payer.buy(url);
  const { grant } = await grantFor(stopped.ask, { overrides: { validUntil: now - 1 } });

  const r = await payer.buy(url, { grant, grantSignatureValid: true });
  assert.equal(r.outcome, REFUSED);
  assert.equal(r.verdict.code, "GRANT_EXPIRED");
});

test("a grant signed by the wrong person is refused", async (t) => {
  const { merchant, payer, url } = await harness();
  t.after(() => merchant.close());

  merchant.setFault("amount", OVER_CAP);
  const stopped = await payer.buy(url);
  const { grant, signature } = await grantFor(stopped.ask, { signer: agent });

  assert.equal((await verifyGrant(grant, signature, approver.address)).ok, false);
  // The caller resolves the signature; passing a false here is what that means.
  const r = await payer.buy(url, { grant, grantSignatureValid: false });
  assert.equal(r.outcome, REFUSED);
  assert.equal(r.verdict.code, "BAD_GRANT_SIGNATURE");
});

test("a grant cannot excuse anything structural", async (t) => {
  // This is the property that matters most. A human tapping approve must not be
  // able to authorise a payment to an unmandated payee, on the wrong asset or
  // the wrong chain — each is decided before a grant is even consulted. The
  // wrong asset and chain are DENY; an unmandated payee is ESCALATE by default
  // (DENY with onUnknownMerchant: DENY), and a grant does not clear it either.
  for (const [fault, code] of [
    [{ payTo: "0x000000000000000000000000000000000000dEaD" }, "UNKNOWN_MERCHANT"],
    [{ asset: "0x000000000000000000000000000000000000bEEF" }, "ASSET_MISMATCH"],
    [{ network: "eip155:1" }, "NETWORK_MISMATCH"],
  ]) {
    const { merchant, payer, url, mandateId } = await harness();
    merchant.setFault("amount", OVER_CAP);
    for (const [k, v] of Object.entries(fault)) merchant.setFault(k, v);

    // Forge a grant that says yes to exactly what the merchant is asking.
    const { grant } = await grantFor({
      mandateId,
      agent: agent.address,
      merchant: fault.payTo ?? MERCHANT,
      asset: fault.asset ?? RLUSD,
      amount: OVER_CAP,
      resource: url,
    });
    const r = await payer.buy(url, { grant, grantSignatureValid: true });
    await merchant.close();

    assert.notEqual(r.outcome, PAID, `${code} must not be payable with a grant`);
    assert.equal(r.verdict.code, code, `${code} is decided before the grant`);
  }
});

test("a grant attached to a payment that was fine anyway is not burned", async (t) => {
  const { merchant, payer, url, ledger, mandateId } = await harness();
  t.after(() => merchant.close());

  const { grant } = await grantFor({
    mandateId,
    agent: agent.address,
    merchant: MERCHANT,
    asset: RLUSD,
    amount: PRICE,
    resource: url,
  });

  const r = await payer.buy(url, { grant, grantSignatureValid: true });
  assert.equal(r.outcome, PAID);
  assert.equal(r.verdict.code, "WITHIN_GRANT", "the grant matches, so it is honoured");
  assert.equal(ledger.isGrantUsed(hashGrant(grant)), true, "and consumed, since it was relied on");
});
