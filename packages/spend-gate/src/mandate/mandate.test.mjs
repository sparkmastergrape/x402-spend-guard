import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import {
  buildMandate,
  hashMandate,
  verifyMandate,
  toSignerPayload,
  describeMandate,
  rlusd,
  formatRlusd,
  MANDATE_TYPES,
} from "./index.js";
import { CHAIN_ID, RLUSD, RLUSD_DECIMALS } from "../config/network.js";

const KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const approver = privateKeyToAccount(KEY);
const AGENT = "0x37F2F4166646Ea3cea94BB37BaBD88a01F52A7A2";
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const REGISTRY = "0x0000000000000000000000000000000000000001";

const good = (over = {}) =>
  buildMandate({
    agent: AGENT,
    merchant: MERCHANT,
    maxPerCall: rlusd("0.05"),
    maxTotal: rlusd("2"),
    maxPerWindow: rlusd("0.5"),
    windowSeconds: 3600,
    validFrom: 1_800_000_000,
    validUntil: 1_800_003_600,
    purpose: "market-data",
    nonce: 1,
    registry: REGISTRY,
    ...over,
  });

describe("Mandate — construction and invariants", () => {
  test("builds with the testnet chain id, not mainnet", () => {
    assert.equal(good().domain.chainId, CHAIN_ID);
    assert.equal(CHAIN_ID, 1449000);
  });

  test("defaults the asset to RLUSD with 18 decimals", () => {
    assert.equal(good().message.asset, RLUSD);
    assert.equal(RLUSD_DECIMALS, 18);
    assert.equal(rlusd("0.01"), 10_000_000_000_000_000n);
  });

  const bad = [
    ["expiry before start", { validUntil: 1_799_999_999 }],
    ["zero per-call cap", { maxPerCall: 0n }],
    ["total below per-call", { maxTotal: rlusd("0.01") }],
    ["window below per-call", { maxPerWindow: rlusd("0.01") }],
    ["zero window", { windowSeconds: 0 }],
    ["empty purpose", { purpose: "   " }],
    ["purpose too long for one screen", { purpose: "x".repeat(33) }],
    ["merchant not an address", { merchant: "not-an-address" }],
  ];
  for (const [name, over] of bad) {
    test(`rejects ${name}`, () => assert.throws(() => good(over)));
  }
});

describe("Mandate — signing and verification", () => {
  test("round-trips: signs, recovers, verifies", async () => {
    const m = good();
    const sig = await approver.signTypedData(m);
    const res = await verifyMandate(m, sig, approver.address);
    assert.ok(res.ok);
    assert.equal(res.recovered.toLowerCase(), approver.address.toLowerCase());
  });

  test("a different signer fails verification with a reason", async () => {
    const m = good();
    const sig = await approver.signTypedData(m);
    const res = await verifyMandate(m, sig, AGENT);
    assert.equal(res.ok, false);
    assert.match(res.reason, /expected/);
  });

  test("a garbage signature is a verdict, not an exception", async () => {
    const res = await verifyMandate(good(), "0xdeadbeef", approver.address);
    assert.equal(res.ok, false);
    assert.match(res.reason, /unrecoverable/);
  });

  test("changing any field changes the digest", async () => {
    const m = good();
    const h = hashMandate(m);
    for (const [field, value] of [
      ["maxPerCall", rlusd("0.06")],
      ["merchant", "0x00000000000000000000000000000000DeaDBeef"],
      ["purpose", "something-else"],
      ["validUntil", 1_800_003_601n],
    ]) {
      const altered = { ...m, message: { ...m.message, [field]: value } };
      assert.notEqual(hashMandate(altered), h, `${field} must affect the digest`);
    }
  });

  test("the chain id is bound into the signature", async () => {
    const a = good();
    const b = good({ chainId: 1440000 }); // mainnet
    assert.notEqual(hashMandate(a), hashMandate(b));
    const sig = await approver.signTypedData(a);
    const res = await verifyMandate(b, sig, approver.address);
    assert.equal(res.ok, false, "a testnet signature must not verify as mainnet");
  });
});

describe("Mandate — device and human readability", () => {
  test("signer payload has no bigints but the same digest", () => {
    const m = good();
    const p = toSignerPayload(m);
    assert.ok(!Object.values(p.message).some((v) => typeof v === "bigint"));
    assert.equal(hashMandate({ ...p, message: m.message }), hashMandate(m));
  });

  test("purpose is a string type so the device renders it as text", () => {
    assert.equal(MANDATE_TYPES.Mandate.find((f) => f.name === "purpose").type, "string");
    assert.equal(good().message.purpose, "market-data");
  });

  test("merchant is an address, not a packed root, so it renders readably", () => {
    assert.equal(MANDATE_TYPES.Mandate.find((f) => f.name === "merchant").type, "address");
  });

  test("describes itself in human terms", () => {
    const d = describeMandate(good());
    assert.match(d, /market-data/);
    assert.match(d, /0\.05 RLUSD\/call/);
    assert.equal(formatRlusd(rlusd("0.05")), "0.05");
  });
});
