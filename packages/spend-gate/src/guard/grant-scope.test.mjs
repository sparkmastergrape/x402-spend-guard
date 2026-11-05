// What a single-use grant does and does not change in the Guard.
//
// Other tests exercise grants through the payer. These go to
// evaluate() directly, so the two claims the docs make are pinned here:
//   - a spent grant is refused (grantConsumed), and an unspent one is allowed;
//   - a valid grant widens the per-payment ceiling only. It does not resolve
//     UNKNOWN_MERCHANT or MANDATE_EXPIRED (checked before a grant is looked at)
//     and it never lifts the channel cap (SpendLedger.reserve refuses it).

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { buildMandate, rlusd, hashMandate, verifyMandate } from "../mandate/index.js";
import { buildGrant, hashGrant } from "../mandate/grant.js";
import { evaluate, ALLOW, ESCALATE, DENY } from "./index.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { RLUSD, PAYMENT_LEDGER, X402_NETWORK, X402_SCHEME, MANDATE_REGISTRY } from "../config/network.js";

const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const STRANGER = "0x000000000000000000000000000000000000dEaD";
const URL = "https://merchant.example/data";
const NOW = 1_792_000_000;

// Throwaway keys; nothing here is real.
const approver = privateKeyToAccount(generatePrivateKey());
const agent = privateKeyToAccount(generatePrivateKey()).address;

const mandate = buildMandate({
  agent,
  merchant: MERCHANT,
  maxPerCall: rlusd("0.05"),
  maxPerWindow: rlusd("0.5"),
  maxTotal: rlusd("2"),
  purpose: "market-data",
  validFrom: NOW - 60,
  validUntil: NOW + 3600,
  registry: MANDATE_REGISTRY,
});
const mandateId = hashMandate(mandate);
const signatureValid = (await verifyMandate(mandate, await approver.signTypedData(mandate), approver.address)).ok;

const challenge = (amount, payTo = MERCHANT) => ({
  resource: { url: URL },
  accepts: [{ scheme: X402_SCHEME, network: X402_NETWORK, amount: amount.toString(), asset: RLUSD, payTo, extra: { ledger: PAYMENT_LEDGER } }],
});

const grantFor = (amount, merchant = MERCHANT) =>
  buildGrant({ mandateId, agent, merchant, asset: RLUSD, amount, resource: URL, validUntil: NOW + 300, nonce: 1n, registry: MANDATE_REGISTRY });

const judge = (c, o = {}) =>
  evaluate({
    mandate,
    mandateId,
    signatureValid,
    challenge: c,
    agent,
    now: NOW,
    spend: new SpendLedger().snapshot(mandateId, { windowSeconds: 3600 }),
    policy: { expectedLedger: PAYMENT_LEDGER },
    ...o,
  });

const withGrant = (amount, { payTo = MERCHANT, grantMerchant = payTo, ...o } = {}) => {
  const grant = grantFor(amount, grantMerchant);
  return judge(challenge(amount, payTo), { grant, grantId: hashGrant(grant), grantSignatureValid: true, ...o });
};

describe("grantConsumed", () => {
  test("a payment over the per-call cap is held without a grant", () => {
    assert.deepEqual([judge(challenge(rlusd("0.4"))).decision, judge(challenge(rlusd("0.4"))).code], [ESCALATE, "OVER_PER_CALL"]);
  });

  test("an unspent grant allows it: WITHIN_GRANT, whether grantConsumed is left out or false", () => {
    for (const o of [{}, { grantConsumed: false }]) {
      const v = withGrant(rlusd("0.4"), o);
      assert.deepEqual([v.decision, v.code], [ALLOW, "WITHIN_GRANT"], JSON.stringify(o));
    }
  });

  test("the same grant, already consumed, is refused: DENY GRANT_SPENT, naming the grant", () => {
    const grant = grantFor(rlusd("0.4"));
    const v = judge(challenge(rlusd("0.4")), { grant, grantId: hashGrant(grant), grantSignatureValid: true, grantConsumed: true });
    assert.deepEqual([v.decision, v.code], [DENY, "GRANT_SPENT"]);
    assert.equal(v.detail.grantId, hashGrant(grant));
  });

  test("a consumed grant is refused even when the payment would be inside the mandate", () => {
    const v = withGrant(rlusd("0.01"), { grantConsumed: true });
    assert.deepEqual([v.decision, v.code], [DENY, "GRANT_SPENT"]);
  });
});

describe("a valid grant widens the per-payment ceiling only", () => {
  test("it does not make an unknown payee known, even when the grant names that payee", () => {
    const v = withGrant(rlusd("0.01"), { payTo: STRANGER });
    assert.deepEqual([v.decision, v.code], [ESCALATE, "UNKNOWN_MERCHANT"]);
  });

  test("it does not revive an expired mandate, even with a grant that has not itself expired", () => {
    const v = withGrant(rlusd("0.01"), { now: NOW + 7200 });
    assert.deepEqual([v.decision, v.code], [ESCALATE, "MANDATE_EXPIRED"]);
    const grant = buildGrant({ mandateId, agent, merchant: MERCHANT, asset: RLUSD, amount: rlusd("0.01"), resource: URL, validUntil: NOW + 9000, nonce: 2n, registry: MANDATE_REGISTRY });
    const v2 = judge(challenge(rlusd("0.01")), { now: NOW + 7200, grant, grantId: hashGrant(grant), grantSignatureValid: true });
    assert.deepEqual([v2.decision, v2.code], [ESCALATE, "MANDATE_EXPIRED"]);
  });

  test("it answers over-total and over-window, which are the quantitative questions", () => {
    const total = withGrant(rlusd("0.04"), { spend: { total: rlusd("1.99"), window: 0n } });
    const window = withGrant(rlusd("0.04"), { spend: { total: 0n, window: rlusd("0.48") } });
    assert.deepEqual([total.code, window.code], ["WITHIN_GRANT", "WITHIN_GRANT"]);
  });

  test("it never lifts the channel cap: the Guard looks past it, and SpendLedger.reserve refuses it", () => {
    const amount = rlusd("0.4");
    const v = withGrant(amount, { channelCap: rlusd("0.1") });
    assert.equal(v.code, "WITHIN_GRANT");
    const grant = grantFor(amount);
    const r = new SpendLedger().reserve({
      mandateId,
      amount,
      caps: mandate.message,
      channelId: "0xchannel",
      channelCap: rlusd("0.1"),
      grantId: hashGrant(grant),
      grantAmount: amount,
    });
    assert.deepEqual([r.ok, r.code], [false, "OVER_CHANNEL_CAP"]);
  });
});
