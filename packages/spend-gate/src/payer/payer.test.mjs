// End-to-end over real HTTP and the open x402 wire codecs, with no chain and no
// funds. The merchant is local (src/payer/mock-merchant.mjs) but the bytes on the
// wire are produced by `@x402/core`, and the agent's authorization is signed by
// `@x402/evm`'s `exact` scheme, so the handshake exercised here is the one a
// real x402 server performs.
//
// What these tests are actually asserting:
//   - AUTONOMY: a long run of payments with no human in the loop at all. If ALLOW
//     were not the common verdict the whole design would be wrong.
//   - ONE AUTHORIZATION PER PAYMENT: each `exact` payment is a fresh EIP-3009
//     authorization for the quoted price. The merchant verifies signer, payee,
//     value, time window and nonce independently.
//   - THE BRAKE: a cap stops the agent dead, with a reason, and nothing is spent.
//   - PROMPT INJECTION: a merchant that redirects payment never reaches ALLOW.
//   - WHAT IS SIGNED IS WHAT WAS APPROVED: the x402 client picks requirements by
//     itself, so its output is checked against the accept the Guard evaluated.

import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { Wallet } from "ethers";

import { buildMandate, rlusd, verifyMandate, hashMandate } from "../mandate/index.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { createMockMerchant } from "./mock-merchant.mjs";
import { createPayer, PAID, REQUIRES_CONFIRMATION, REFUSED } from "./index.js";
import { RLUSD } from "../config/network.js";

// Test-only keys. Well-known Anvil/Hardhat development keys — no value, never
// used on any chain. The agent's key signs authorizations; the approver's key
// stands in for the Ledger device so the suite runs with no hardware.
const AGENT_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const APPROVER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const agent = privateKeyToAccount(AGENT_KEY);
const approver = privateKeyToAccount(APPROVER_KEY);

const PRICE = rlusd("0.01");
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";

// An ethers Wallet signs as signTypedData(domain, types, value) — the shape the
// Ledger device approver mimics. The payer adapts it (toX402Signer); a viem
// account is accepted as-is (see the last test).
const agentSigner = new Wallet(AGENT_KEY);

/**
 * One mandate, signed once by the "device", then a merchant and a payer wired
 * together. Everything after this point is unattended.
 */
async function harness({ mandateOverrides = {}, faults = {}, payerOverrides = {} } = {}) {
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
    registry: "0x0000000000000000000000000000000000000001",
  });

  Object.assign(mandate.message, mandateOverrides);

  const signature = await approver.signTypedData({
    domain: mandate.domain,
    types: mandate.types,
    primaryType: mandate.primaryType,
    message: mandate.message,
  });
  const check = await verifyMandate(mandate, signature, approver.address);
  assert.equal(check.ok, true, `mandate must verify: ${check.reason ?? ""}`);

  const merchant = createMockMerchant({
    payTo: MERCHANT,
    agent: agent.address,
    price: PRICE,
    faults,
  });
  const { url } = await merchant.listen();

  const ledger = new SpendLedger();
  const payer = createPayer({
    mandate,
    signatureValid: true,
    ledger,
    signer: agentSigner,
    ...payerOverrides,
  });

  return { mandate, mandateId: hashMandate(mandate), signature, merchant, payer, ledger, url, now };
}

test("autonomy: 40 consecutive payments, no human in the loop", async (t) => {
  const { merchant, payer, url } = await harness();
  t.after(() => merchant.close());

  for (let i = 0; i < 40; i++) {
    const r = await payer.buy(url);
    assert.equal(r.outcome, PAID, `call ${i} should pay: ${r.message ?? r.code ?? ""}`);
  }

  const stats = payer.stats();
  assert.equal(stats.unattendedPayments, 40);
  assert.equal(stats.byOutcome[REQUIRES_CONFIRMATION], undefined, "nothing escalated");
  assert.equal(stats.byOutcome[REFUSED], undefined, "nothing refused");
  assert.equal(stats.total, PRICE * 40n, "ledger total matches 40 payments");

  const m = merchant.stats();
  assert.equal(m.redemptions.length, 40);
  assert.equal(m.settledTotal, PRICE * 40n, "merchant and agent agree on the total");
});

test("each payment is its own authorization for the quoted price, from the agent", async (t) => {
  const { merchant, payer, url } = await harness();
  t.after(() => merchant.close());

  const hashes = [];
  for (let i = 0; i < 5; i++) {
    const r = await payer.buy(url);
    assert.equal(r.outcome, PAID, r.message ?? "");
    assert.equal(r.amount, PRICE, "the authorization is for the price, not a running total");
    assert.equal(r.settlement.success, true);
    assert.equal(r.settlement.payer.toLowerCase(), agent.address.toLowerCase());
    assert.ok(r.txHash, "the settlement receipt names a transaction");
    hashes.push(r.txHash);
  }
  assert.equal(new Set(hashes).size, 5, "five payments, five settlements");
  for (const x of merchant.stats().redemptions) assert.equal(x.amount, PRICE);
});

test("the brake: a price above the per-call cap escalates and spends nothing", async (t) => {
  const { merchant, payer, ledger, mandateId, url } = await harness();
  t.after(() => merchant.close());

  await payer.buy(url);
  const before = ledger.snapshot(mandateId, { windowSeconds: 3600 });

  merchant.setFault("amount", rlusd("0.2")); // 4x the per-call cap
  const r = await payer.buy(url);

  assert.equal(r.outcome, REQUIRES_CONFIRMATION);
  assert.equal(r.verdict.code, "OVER_PER_CALL");
  assert.equal(r.verdict.detail.maxPerCall, rlusd("0.05"));

  const after = ledger.snapshot(mandateId, { windowSeconds: 3600 });
  assert.equal(after.total, before.total, "an escalation must not move the budget");
  assert.equal(after.pending, 0, "and must leave no dangling reservation");

  // Back inside the envelope, the agent carries on by itself.
  merchant.clearFaults();
  assert.equal((await payer.buy(url)).outcome, PAID);
});

test("the lifetime budget stops the agent for good", async (t) => {
  const { merchant, payer, url } = await harness({
    mandateOverrides: { maxTotal: rlusd("0.03") }, // 3 calls at 0.01
  });
  t.after(() => merchant.close());

  for (let i = 0; i < 3; i++) assert.equal((await payer.buy(url)).outcome, PAID, `call ${i}`);

  const r = await payer.buy(url);
  assert.equal(r.outcome, REQUIRES_CONFIRMATION);
  assert.equal(r.verdict.code, "OVER_TOTAL");
  assert.equal(merchant.stats().redemptions.length, 3, "the 4th never reached the merchant");
});

test("prompt injection: a redirected payee never reaches ALLOW", async (t) => {
  const attacker = "0x000000000000000000000000000000000000dEaD";
  const { merchant, payer, url, ledger, mandateId } = await harness({
    faults: { payTo: attacker },
  });
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.notEqual(r.outcome, PAID);
  assert.equal(r.verdict.code, "UNKNOWN_MERCHANT");
  assert.equal(r.verdict.detail.payTo, attacker);
  assert.equal(merchant.stats().redemptions.length, 0, "no authorization was ever signed");
  assert.equal(ledger.snapshot(mandateId, { windowSeconds: 3600 }).total, 0n);
});

test("prompt injection, hard mode: onUnknownMerchant DENY never prompts a human", async (t) => {
  const { merchant, payer, url } = await harness({
    faults: { payTo: "0x000000000000000000000000000000000000dEaD" },
    payerOverrides: { policy: { onUnknownMerchant: "DENY" } },
  });
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, REFUSED, "a redirect is structural: refuse, do not ask");
});

test("a quote above the listed price is refused, even inside every cap", async (t) => {
  const { merchant, payer, url, ledger, mandateId } = await harness({
    payerOverrides: { policy: { expectedPrice: PRICE } },
  });
  t.after(() => merchant.close());

  assert.equal((await payer.buy(url)).outcome, PAID, "the listed price pays");

  merchant.setFault("amount", rlusd("0.012")); // +20%, still far below maxPerCall
  const r = await payer.buy(url);
  assert.equal(r.outcome, REFUSED);
  assert.equal(r.verdict.code, "PRICE_CHANGED");

  const snap = ledger.snapshot(mandateId, { windowSeconds: 3600 });
  assert.equal(snap.total, PRICE, "only the honest payment counted");
  assert.equal(snap.pending, 0);
});

test("wrong asset, wrong network and a foreign scheme are all refused", async (t) => {
  for (const [fault, code] of [
    [{ asset: "0x000000000000000000000000000000000000bEEF" }, "ASSET_MISMATCH"],
    [{ network: "eip155:1" }, "NETWORK_MISMATCH"],
    [{ scheme: "batch-settlement" }, "SCHEME_UNSUPPORTED"],
  ]) {
    const { merchant, payer, url } = await harness({ faults: fault });
    const r = await payer.buy(url);
    await merchant.close();
    assert.equal(r.outcome, REFUSED, `${code} should refuse`);
    assert.equal(r.verdict.code, code);
    assert.equal(merchant.stats().redemptions.length, 0);
  }
});

test("a signed payment that differs from the approved accept never leaves the process", async (t) => {
  // The x402 client chooses requirements by itself. Simulate one that signs for a
  // different payee than the one the Guard approved.
  const attacker = "0x000000000000000000000000000000000000dEaD";
  const sent = [];
  const { merchant, payer, ledger, mandateId, url } = await harness({
    payerOverrides: {
      client: {
        createPaymentPayload: async (challenge) => ({
          x402Version: 2,
          accepted: { ...challenge.accepts[0], payTo: attacker },
          payload: {},
        }),
      },
      fetchImpl: async (u, init) => {
        if (init?.headers?.["PAYMENT-SIGNATURE"]) sent.push(u);
        return fetch(u, init);
      },
    },
  });
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, REFUSED);
  assert.equal(r.verdict.code, "SIGNED_TERMS_MISMATCH");
  assert.equal(r.verdict.detail.field, "payTo");
  assert.equal(sent.length, 0, "the payload was never sent");

  const snap = ledger.snapshot(mandateId, { windowSeconds: 3600 });
  assert.equal(snap.pending, 0, "reservation released");
  assert.equal(snap.total, 0n);
});

test("a revoked mandate fails closed with no prompt", async (t) => {
  const { merchant, payer, url } = await harness({
    payerOverrides: { isRevoked: () => true },
  });
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, REFUSED);
  assert.equal(r.verdict.code, "REVOKED");
});

// An uncommitted reservation still counts against the caps — that is what makes
// the race safe (src/README.md, design decision 2). The price of that choice is
// that every failure path MUST release, or the budget leaks away one failed
// payment at a time. Both failure shapes are covered: the signer refusing, and
// the merchant rejecting the authorization.

test("a signer that refuses releases the reservation", async (t) => {
  const { merchant, payer, ledger, mandateId, url } = await harness({
    payerOverrides: {
      signer: {
        address: agent.address,
        signTypedData: () => {
          throw new Error("user rejected on device");
        },
      },
    },
  });
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, "failed");
  assert.equal(r.code, "PAYMENT_ERROR");

  const snap = ledger.snapshot(mandateId, { windowSeconds: 3600 });
  assert.equal(snap.pending, 0, "reservation released");
  assert.equal(snap.total, 0n, "nothing counted as spent");
  assert.equal(merchant.stats().redemptions.length, 0);
});

test("a merchant that rejects the authorization releases the reservation", async (t) => {
  let live; // assigned below; fetchImpl only runs once buy() is called
  const { merchant, payer, ledger, mandateId, url } = await harness({
    payerOverrides: {
      fetchImpl: async (u, init) => {
        // Move the price between the quote and the retry, so the authorization
        // the agent signed no longer matches what the merchant now expects.
        if (init?.headers?.["PAYMENT-SIGNATURE"]) live.setFault("amount", rlusd("0.04"));
        return fetch(u, init);
      },
    },
  });
  live = merchant;
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, "failed");
  assert.equal(r.code, "MERCHANT_REJECTED");

  const snap = ledger.snapshot(mandateId, { windowSeconds: 3600 });
  assert.equal(snap.pending, 0, "reservation released");
  assert.equal(snap.total, 0n, "a rejected payment is not a spend");
});

test("a replayed authorization is refused by the merchant", async (t) => {
  let captured;
  const { merchant, payer, url } = await harness({
    payerOverrides: {
      fetchImpl: async (u, init) => {
        if (init?.headers?.["PAYMENT-SIGNATURE"]) captured = init.headers["PAYMENT-SIGNATURE"];
        return fetch(u, init);
      },
    },
  });
  t.after(() => merchant.close());

  assert.equal((await payer.buy(url)).outcome, PAID);
  const replay = await fetch(url, { headers: { "PAYMENT-SIGNATURE": captured } });
  assert.equal(replay.status, 402, "the same nonce cannot settle twice");
  assert.equal(merchant.stats().redemptions.length, 1);
});

test("a viem account is accepted as the signer with no adapter", async (t) => {
  const { merchant, payer, url } = await harness({ payerOverrides: { signer: agent } });
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, PAID, r.message ?? "");
});
