// The failure paths. These are the tests that matter: a revocation check is
// only a control if "I could not find out" stops the agent.

import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { Wallet } from "ethers";

import {
  createRevocationChecker,
  LIVE,
  CACHED,
  STALE,
  UNREACHABLE,
  NEVER_READ,
} from "./index.js";
import { buildMandate, rlusd, hashMandate } from "../mandate/index.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { createMockMerchant } from "../payer/mock-merchant.mjs";
import { createPayer, PAID, REFUSED } from "../payer/index.js";
import { RLUSD } from "../config/network.js";

const APPROVER = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const MANDATE_ID = `0x${"ab".repeat(32)}`;

/** A registry we can break on demand. */
function fakeRegistry({ revoked = false, fail = false } = {}) {
  const state = { revoked, fail, reads: 0 };
  return {
    state,
    read: async () => {
      state.reads++;
      if (state.fail) throw new Error("RPC unreachable");
      return state.revoked;
    },
  };
}

test("a live read of a clean mandate allows spending", async () => {
  const reg = fakeRegistry();
  const c = createRevocationChecker({ read: reg.read, approver: APPROVER });
  const r = await c.check(MANDATE_ID);
  assert.deepEqual([r.revoked, r.source], [false, LIVE]);
});

test("a revoked mandate stops, and is never re-read", async () => {
  const reg = fakeRegistry({ revoked: true });
  const c = createRevocationChecker({ read: reg.read, approver: APPROVER });

  assert.equal((await c.check(MANDATE_ID)).revoked, true);
  assert.equal(reg.state.reads, 1);

  // Revocation is monotonic: no amount of later chain state un-revokes it, and
  // we do not even ask. A registry that later said "no" would be ignored.
  reg.state.revoked = false;
  const again = await c.check(MANDATE_ID);
  assert.equal(again.revoked, true);
  assert.equal(again.source, CACHED);
  assert.equal(reg.state.reads, 1, "no second read");
  assert.equal(c.isRevokedSync(MANDATE_ID), true);
});

test("FAIL CLOSED: an unreadable registry with no prior read stops the agent", async () => {
  const reg = fakeRegistry({ fail: true });
  const c = createRevocationChecker({ read: reg.read, approver: APPROVER });

  const r = await c.check(MANDATE_ID);
  assert.equal(r.revoked, true, "unknown must mean stop");
  assert.equal(r.source, NEVER_READ);
  assert.match(r.detail.message, /refusing to spend/);
});

test("a fresh cached read carries a brief outage", async () => {
  let t = 1_000_000;
  const reg = fakeRegistry();
  const c = createRevocationChecker({
    read: reg.read,
    approver: APPROVER,
    maxStaleMs: 15_000,
    clock: () => t,
  });

  assert.equal((await c.check(MANDATE_ID)).revoked, false);
  reg.state.fail = true;
  t += 5_000;

  const r = await c.check(MANDATE_ID);
  assert.equal(r.revoked, false, "5s into an outage, a 15s-fresh read still counts");
  assert.equal(r.source, CACHED);
  assert.equal(r.detail.ageMs, 5_000);
});

test("FAIL CLOSED: once the cached read is stale, the agent stops", async () => {
  let t = 1_000_000;
  const reg = fakeRegistry();
  const c = createRevocationChecker({
    read: reg.read,
    approver: APPROVER,
    maxStaleMs: 15_000,
    clock: () => t,
  });

  await c.check(MANDATE_ID);
  reg.state.fail = true;
  t += 60_000;

  const r = await c.check(MANDATE_ID);
  assert.equal(r.revoked, true);
  assert.equal(r.source, UNREACHABLE);
  assert.equal(r.detail.ageMs, 60_000);
  assert.equal(r.detail.maxStaleMs, 15_000);
});

test("availability over safety is possible, but only by writing it down", async () => {
  let t = 1_000_000;
  const reg = fakeRegistry();
  const c = createRevocationChecker({
    read: reg.read,
    approver: APPROVER,
    maxStaleMs: 15_000,
    allowStaleWhenOffline: true,
    clock: () => t,
  });

  await c.check(MANDATE_ID);
  reg.state.fail = true;
  t += 60_000;

  const r = await c.check(MANDATE_ID);
  assert.equal(r.revoked, false, "the opt-in does what it says");
  assert.equal(r.source, STALE);
  assert.match(r.detail.message, /availability over safety/);
});

test("the checker reports what it knows", async () => {
  const reg = fakeRegistry({ revoked: true });
  const c = createRevocationChecker({ read: reg.read, approver: APPROVER });
  await c.check(MANDATE_ID);
  const snap = c.snapshot();
  assert.deepEqual(snap.revoked, [MANDATE_ID]);
  assert.equal(snap.lastError, null);
});

// ---------------------------------------------------------------- end to end

async function payerWith(revocation) {
  const agentSigner = Wallet.createRandom();
  const now = Math.floor(Date.now() / 1000);
  const mandate = buildMandate({
    agent: agentSigner.address,
    asset: RLUSD,
    merchant: APPROVER,
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
  const merchant = createMockMerchant({
    payTo: APPROVER,
    agent: agentSigner.address,
    price: rlusd("0.01"),
  });
  const { url } = await merchant.listen();
  const payer = createPayer({
    mandate,
    signatureValid: true,
    ledger: new SpendLedger(),
    signer: agentSigner,
    revocation,
  });
  return { payer, merchant, url, mandateId: hashMandate(mandate) };
}

test("revoking mid-run stops the very next payment", async (t) => {
  const reg = fakeRegistry();
  const revocation = createRevocationChecker({ read: reg.read, approver: APPROVER });
  const { payer, merchant, url } = await payerWith(revocation);
  t.after(() => merchant.close());

  assert.equal((await payer.buy(url)).outcome, PAID);
  assert.equal((await payer.buy(url)).outcome, PAID);

  // the human revokes on their device; the registry now says so
  reg.state.revoked = true;

  const stopped = await payer.buy(url);
  assert.equal(stopped.outcome, REFUSED);
  assert.equal(stopped.verdict.code, "REVOKED");
  assert.equal(merchant.stats().redemptions.length, 2, "the third never reached the merchant");

  // and it stays stopped even if the chain changes its mind
  reg.state.revoked = false;
  assert.equal((await payer.buy(url)).outcome, REFUSED);
});

test("a dead registry stops payments, with a distinguishable reason", async (t) => {
  const reg = fakeRegistry({ fail: true });
  const revocation = createRevocationChecker({ read: reg.read, approver: APPROVER });
  const { payer, merchant, url } = await payerWith(revocation);
  t.after(() => merchant.close());

  const r = await payer.buy(url);
  assert.equal(r.outcome, REFUSED);
  // Not "REVOKED": a human needs to know the difference between "you stopped
  // me" and "I cannot reach the registry".
  assert.equal(r.verdict.code, "REVOCATION_UNKNOWN");
  assert.equal(r.revocation.source, NEVER_READ);
  assert.equal(merchant.stats().challengesIssued, 0, "we never even asked for a quote");
});
