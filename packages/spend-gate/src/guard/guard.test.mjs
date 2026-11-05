import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { buildMandate, rlusd, hashMandate, verifyMandate } from "../mandate/index.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { evaluate, ALLOW, ESCALATE, DENY } from "./index.js";
import { RLUSD, PAYMENT_LEDGER, X402_NETWORK, X402_SCHEME, CHAIN_ID } from "../config/network.js";

const AGENT = "0x37F2F4166646Ea3cea94BB37BaBD88a01F52A7A2";
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const ATTACKER = "0x00000000000000000000000000000000DeaDBeef";
const REGISTRY = "0x0000000000000000000000000000000000000001";
const NOW = 1_800_000_000;

function mandate(over = {}) {
  return buildMandate({
    agent: AGENT,
    merchant: MERCHANT,
    asset: RLUSD,
    maxPerCall: rlusd("0.05"),
    maxTotal: rlusd("2"),
    maxPerWindow: rlusd("0.5"),
    windowSeconds: 3600,
    validFrom: NOW - 10,
    validUntil: NOW + 3600,
    purpose: "market-data",
    nonce: 1,
    registry: REGISTRY,
    ...over,
  });
}

function challenge(over = {}, acceptsOver = {}) {
  return {
    resource: { url: "https://merchant.example/resource" },
    accepts: [
      {
        scheme: X402_SCHEME,
        network: X402_NETWORK,
        asset: RLUSD,
        payTo: MERCHANT,
        maxAmountRequired: rlusd("0.01").toString(),
        extra: { ledger: PAYMENT_LEDGER },
        ...acceptsOver,
      },
    ],
    ...over,
  };
}

const base = (over = {}) => ({
  mandate: mandate(),
  mandateId: "0xabc",
  signatureValid: true,
  challenge: challenge(),
  agent: AGENT,
  now: NOW,
  spend: { total: 0n, window: 0n },
  policy: { expectedLedger: PAYMENT_LEDGER },
  ...over,
});

describe("Guard — the autonomous path", () => {
  test("allows a payment inside the envelope, with no human", () => {
    const v = evaluate(base());
    assert.equal(v.decision, ALLOW);
    assert.equal(v.detail.remainingTotal, rlusd("2") - rlusd("0.01"));
  });

  test("stays autonomous across many payments until a cap is reached", () => {
    const led = new SpendLedger({ now: () => NOW });
    const m = mandate();
    const id = hashMandate(m);
    let allowed = 0;
    for (let i = 0; i < 100; i++) {
      const snap = led.snapshot(id, { windowSeconds: 3600 });
      const v = evaluate(base({ mandate: m, mandateId: id, spend: snap }));
      if (v.decision !== ALLOW) break;
      allowed++;
      const r = led.reserve({
        mandateId: id,
        amount: rlusd("0.01"),
        caps: m.message,
      });
      assert.ok(r.ok, `reserve failed at ${i}: ${r.code}`);
      led.commit(r.reservationId, { txHash: `0x${i}` });
    }
    // 0.5 RLUSD per hour / 0.01 per call = 50 autonomous payments.
    assert.equal(allowed, 50);
  });
});

describe("Guard — DENY is structural, never prompted", () => {
  const cases = [
    ["BAD_SIGNATURE", { signatureValid: false }],
    ["REVOKED", { revoked: true }],
    ["ASSET_MISMATCH", { challenge: challenge({}, { asset: ATTACKER }) }],
    ["NETWORK_MISMATCH", { challenge: challenge({}, { network: "eip155:1" }) }],
    ["SCHEME_UNSUPPORTED", { challenge: challenge({}, { scheme: "batch-settlement" }) }],
    ["LEDGER_MISMATCH", { challenge: challenge({}, { extra: { ledger: ATTACKER } }) }],
    ["AGENT_MISMATCH", { agent: ATTACKER }],
    ["NOT_YET_VALID", { now: NOW - 100 }],
    ["MALFORMED_CHALLENGE", { challenge: { accepts: [] } }],
    ["MULTIPLE_ACCEPTS", { challenge: { ...challenge(), accepts: [challenge().accepts[0], challenge().accepts[0]] } }],
    ["NON_POSITIVE_AMOUNT", { challenge: challenge({}, { maxAmountRequired: "0" }) }],
  ];
  for (const [code, over] of cases) {
    test(`${code} -> DENY`, () => {
      const v = evaluate(base(over));
      assert.equal(v.decision, DENY, `expected DENY, got ${v.decision} (${v.code})`);
      assert.equal(v.code, code);
    });
  }

  test("a 402 with no stated amount fails closed, not as zero", () => {
    const c = challenge();
    delete c.accepts[0].maxAmountRequired;
    const v = evaluate(base({ challenge: c }));
    assert.equal(v.decision, DENY);
    assert.equal(v.code, "MALFORMED_CHALLENGE");
  });

  test("a mandate signed for mainnet is refused on testnet", () => {
    const v = evaluate(base({ mandate: mandate({ chainId: 1440000 }) }));
    assert.equal(v.decision, DENY);
    assert.equal(v.code, "CHAIN_MISMATCH");
  });
});

describe("Guard — ESCALATE is a human judgement call", () => {
  test("over per-call limit", () => {
    const v = evaluate(base({ challenge: challenge({}, { maxAmountRequired: rlusd("0.2").toString() }) }));
    assert.equal(v.decision, ESCALATE);
    assert.equal(v.code, "OVER_PER_CALL");
  });

  test("over lifetime budget", () => {
    const v = evaluate(base({ spend: { total: rlusd("1.995"), window: 0n } }));
    assert.equal(v.decision, ESCALATE);
    assert.equal(v.code, "OVER_TOTAL");
  });

  test("over rate window", () => {
    const v = evaluate(base({ spend: { total: 0n, window: rlusd("0.495") } }));
    assert.equal(v.decision, ESCALATE);
    assert.equal(v.code, "OVER_WINDOW");
  });

  test("expired mandate", () => {
    const v = evaluate(base({ now: NOW + 7200 }));
    assert.equal(v.decision, ESCALATE);
    assert.equal(v.code, "MANDATE_EXPIRED");
  });

  test("over on-chain channel cap", () => {
    const v = evaluate(base({ channelCumulative: rlusd("4.995"), channelCap: rlusd("5") }));
    assert.equal(v.decision, ESCALATE);
    assert.equal(v.code, "OVER_CHANNEL_CAP");
  });
});

describe("Guard — prompt injection cannot redirect payment", () => {
  test("a poisoned 402 naming an attacker payee never reaches ALLOW", () => {
    const v = evaluate(base({ challenge: challenge({}, { payTo: ATTACKER }) }));
    assert.notEqual(v.decision, ALLOW);
    assert.equal(v.code, "UNKNOWN_MERCHANT");
    assert.equal(v.detail.payTo, ATTACKER);
    assert.equal(v.detail.allowed, MERCHANT);
  });

  test("strict policy turns it into an outright DENY", () => {
    const v = evaluate(
      base({
        challenge: challenge({}, { payTo: ATTACKER }),
        policy: { expectedLedger: PAYMENT_LEDGER, onUnknownMerchant: DENY },
      }),
    );
    assert.equal(v.decision, DENY);
  });

  test("the allowlist is inside the signed payload, so tampering invalidates it", async () => {
    const approver = privateKeyToAccount(
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    );
    const m = mandate();
    const sig = await approver.signTypedData(m);
    assert.ok((await verifyMandate(m, sig, approver.address)).ok);

    // Attacker swaps the merchant for their own address.
    const tampered = { ...m, message: { ...m.message, merchant: ATTACKER } };
    const check = await verifyMandate(tampered, sig, approver.address);
    assert.equal(check.ok, false, "tampered mandate must not verify");

    const v = evaluate(
      base({
        mandate: tampered,
        signatureValid: false,
        challenge: challenge({}, { payTo: ATTACKER }),
      }),
    );
    assert.equal(v.decision, DENY);
    assert.equal(v.code, "BAD_SIGNATURE");
  });
});

describe("Guard — price change (ported from tripwire-dispatch)", () => {
  const policy = (over = {}) => ({ expectedLedger: PAYMENT_LEDGER, expectedPrice: rlusd("0.01"), ...over });

  test("allows the listed price", () => {
    assert.equal(evaluate(base({ policy: policy() })).decision, ALLOW);
  });

  test("denies one base unit above the listed price with no tolerance", () => {
    const c = challenge({}, { maxAmountRequired: (rlusd("0.01") + 1n).toString() });
    const v = evaluate(base({ challenge: c, policy: policy() }));
    assert.equal(v.decision, DENY);
    assert.equal(v.code, "PRICE_CHANGED");
  });

  test("allows a rise inside the tolerance, denies one above it", () => {
    const at = challenge({}, { maxAmountRequired: rlusd("0.0125").toString() });
    const over = challenge({}, { maxAmountRequired: (rlusd("0.0125") + 1n).toString() });
    assert.equal(evaluate(base({ challenge: at, policy: policy({ priceTolerancePct: 25 }) })).decision, ALLOW);
    const v = evaluate(base({ challenge: over, policy: policy({ priceTolerancePct: 25 }) }));
    assert.equal(v.code, "PRICE_CHANGED");
  });

  test("accepts the listed price as an integer string", () => {
    const c = challenge({}, { maxAmountRequired: rlusd("0.02").toString() });
    const v = evaluate(base({ challenge: c, policy: policy({ expectedPrice: rlusd("0.01").toString() }) }));
    assert.equal(v.code, "PRICE_CHANGED");
  });

  test("no listed price means no price-change check", () => {
    const c = challenge({}, { maxAmountRequired: rlusd("0.04").toString() });
    assert.notEqual(evaluate(base({ challenge: c })).code, "PRICE_CHANGED");
  });
});
