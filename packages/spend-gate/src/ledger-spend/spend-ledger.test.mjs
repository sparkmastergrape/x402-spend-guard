import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { SpendLedger } from "./index.js";
import { rlusd } from "../mandate/index.js";

const CAPS = {
  maxPerCall: rlusd("0.05"),
  maxTotal: rlusd("2"),
  maxPerWindow: rlusd("0.5"),
  windowSeconds: 3600,
};
const M = "0xmandate";
const CH = "0xchannel";

const at = (t) => new SpendLedger({ now: () => t });

describe("SpendLedger — reservations", () => {
  test("a reservation counts against caps before it is committed", () => {
    const led = at(1000);
    // Per-call cap raised for this case; the point here is the lifetime budget.
    const caps = { ...CAPS, maxPerCall: rlusd("2"), maxPerWindow: rlusd("2") };
    const r = led.reserve({ mandateId: M, amount: rlusd("1.98"), caps });
    assert.ok(r.ok, r.code);
    // Still only reserved, never committed — but the budget is already spoken for.
    const second = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps });
    assert.equal(second.ok, false);
    assert.equal(second.code, "OVER_TOTAL");
  });

  test("two concurrent calls cannot both pass a cap only one fits (T5)", () => {
    const led = at(1000);
    const caps = { ...CAPS, maxTotal: rlusd("0.05"), maxPerWindow: rlusd("0.05") };
    const a = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps });
    const b = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps });
    assert.ok(a.ok);
    assert.equal(b.ok, false, "second reservation must be refused");
  });

  test("release frees the budget, commit keeps it spent", () => {
    const led = at(1000);
    const caps = { ...CAPS, maxTotal: rlusd("0.05"), maxPerWindow: rlusd("0.05") };
    const a = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps });
    led.release(a.reservationId, { reason: "merchant 500" });
    const b = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps });
    assert.ok(b.ok, "budget should be free again after release");
    led.commit(b.reservationId, { txHash: "0xdead" });
    const c = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps });
    assert.equal(c.ok, false, "committed spend must not be reusable");
  });

  test("double commit and double release are rejected", () => {
    const led = at(1000);
    const r = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps: CAPS });
    led.commit(r.reservationId);
    assert.throws(() => led.commit(r.reservationId), /is committed/);
    assert.throws(() => led.release(r.reservationId), /is committed/);
  });

  test("rejects a non-positive amount", () => {
    const led = at(1000);
    assert.equal(led.reserve({ mandateId: M, amount: 0n, caps: CAPS }).code, "NON_POSITIVE_AMOUNT");
  });
});

describe("SpendLedger — rate window", () => {
  test("spend ages out of the rolling window", () => {
    let t = 1000;
    const led = new SpendLedger({ now: () => t });
    const caps = { ...CAPS, maxPerWindow: rlusd("0.02") };
    led.commit(led.reserve({ mandateId: M, amount: rlusd("0.02"), caps }).reservationId);
    assert.equal(led.reserve({ mandateId: M, amount: rlusd("0.01"), caps }).code, "OVER_WINDOW");

    t += 3601; // past windowSeconds
    const after = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps });
    assert.ok(after.ok, "window should have cleared");
  });

  test("the lifetime cap does not age out", () => {
    let t = 1000;
    const led = new SpendLedger({ now: () => t });
    const caps = { ...CAPS, maxTotal: rlusd("0.02") };
    led.commit(led.reserve({ mandateId: M, amount: rlusd("0.02"), caps }).reservationId);
    t += 86_400;
    assert.equal(led.reserve({ mandateId: M, amount: rlusd("0.01"), caps }).code, "OVER_TOTAL");
  });
});

describe("SpendLedger — AP4M cumulative vouchers", () => {
  test("cumulative amount is a running total, not the per-payment price", () => {
    const led = at(1000);
    const a = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps: CAPS, channelId: CH });
    assert.equal(a.cumulativeAmount, rlusd("0.01"));
    led.commit(a.reservationId);

    const b = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps: CAPS, channelId: CH });
    assert.equal(b.cumulativeAmount, rlusd("0.02"), "second voucher must carry the running total");
    led.commit(b.reservationId);
    assert.equal(led.committedCumulative(CH), rlusd("0.02"));
  });

  test("an in-flight voucher does not reuse a cumulative value", () => {
    const led = at(1000);
    const a = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps: CAPS, channelId: CH });
    const b = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps: CAPS, channelId: CH });
    assert.notEqual(a.cumulativeAmount, b.cumulativeAmount);
    assert.equal(b.cumulativeAmount, rlusd("0.02"));
  });

  test("respects the on-chain channel cap", () => {
    const led = at(1000);
    const r = led.reserve({
      mandateId: M,
      amount: rlusd("0.05"),
      caps: CAPS,
      channelId: CH,
      channelCap: rlusd("0.04"),
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, "OVER_CHANNEL_CAP");
  });

  test("seeded channel state survives a restart", () => {
    const led = at(1000);
    led.seedChannel(CH, rlusd("0.03"));
    const r = led.reserve({ mandateId: M, amount: rlusd("0.01"), caps: CAPS, channelId: CH });
    assert.equal(r.cumulativeAmount, rlusd("0.04"), "must build on recovered cumulative");
  });

  test("seeded committed spend still counts against the mandate budget", () => {
    const led = at(1000);
    led.seedCommitted({ mandateId: M, amount: rlusd("1.99") });
    const r = led.reserve({ mandateId: M, amount: rlusd("0.05"), caps: CAPS });
    assert.equal(r.ok, false);
    assert.equal(r.code, "OVER_TOTAL");
  });
});
