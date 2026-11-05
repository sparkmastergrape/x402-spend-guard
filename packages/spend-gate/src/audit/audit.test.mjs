// Audit events: what the Guard decides, written as agent-audit/1.
//
// Three groups. makeEvent and envelope (the builders refuse bad input),
// validateEnvelope (one mutation per rule: a bad envelope must be rejected, and
// for the right reason, not just rejected), and verdictEvents (the evidence
// labels: what is measured, what is inferred, what is left out).
//
// The verdicts come from the real Guard against a real signed mandate, so the
// events are checked against what the stack actually returns.
//
// Control characters are built with String.fromCodePoint, so this file holds no
// invisible characters of its own.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { parseUnits } from "viem";

import {
  makeEvent,
  makeRunId,
  verdictEvents,
  envelope,
  validateEnvelope,
  invoiceIdFor,
  cleanSummary,
  AuditSchemaError,
  EVM_TESTNET_NETWORK,
  MAINNET_NETWORKS,
  SIGNERS,
  SOFTWARE_SIGNER,
  EMULATOR_SIGNER,
  DEVICE_SIGNER,
} from "./index.js";
import { buildMandate, rlusd, hashMandate, verifyMandate } from "../mandate/index.js";
import { evaluate, ALLOW, ESCALATE, DENY } from "../guard/index.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { RLUSD, PAYMENT_LEDGER, X402_NETWORK, X402_SCHEME, MANDATE_REGISTRY } from "../config/network.js";

const TS = "2026-10-28T12:00:00Z";
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const OTHER_TOKEN = "0x000000000000000000000000000000000000bEEF";
const STRANGER = "0x000000000000000000000000000000000000dEaD";
const TX = `0x${"ab".repeat(32)}`;
const ch = (n) => String.fromCodePoint(n);

// A throwaway approver standing in for the Ledger; nothing here is a real key.
const approver = privateKeyToAccount(generatePrivateKey());
const agent = privateKeyToAccount(generatePrivateKey()).address;
const NOW = Math.floor(Date.parse(TS) / 1000);

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
const signature = await approver.signTypedData(mandate);
const signatureValid = (await verifyMandate(mandate, signature, approver.address)).ok;

const quote = (amount, { asset = RLUSD, payTo = MERCHANT, url = "https://merchant.example/data" } = {}) => ({
  resource: { url },
  accepts: [
    {
      scheme: X402_SCHEME,
      network: X402_NETWORK,
      amount: typeof amount === "bigint" ? amount.toString() : amount,
      asset,
      payTo,
      extra: { ledger: PAYMENT_LEDGER },
    },
  ],
});

const judge = (challenge, o = {}) =>
  evaluate({
    mandate,
    mandateId,
    signatureValid,
    challenge,
    agent,
    now: NOW,
    spend: new SpendLedger().snapshot(mandateId, { windowSeconds: 3600 }),
    policy: { expectedLedger: PAYMENT_LEDGER },
    ...o,
  });

const events = (challenge, extra = {}, o = {}) =>
  verdictEvents({ challenge, verdict: judge(challenge, o), mandateId, ts: TS, mandate, ...extra });
const stages = (evs) => evs.map((e) => e.stage);
const byStage = (evs, s) => evs.find((e) => e.stage === s);
// stage, actor, outcome, evidence for every row: the whole story in one comparison
const mix = (evs) => evs.map((e) => [e.stage, e.actor, e.outcome, e.evidence ?? null]);

const ALLOWED = quote(rlusd("0.01"));
const OVER = quote(rlusd("0.4"));
const WRONG_ASSET = quote(rlusd("0.01"), { asset: OTHER_TOKEN });

// A known-good envelope that every mutation below starts from.
const good = () => envelope({ run_id: makeRunId("test", TS), events: events(ALLOWED) });
const mutate = (fn) => {
  const doc = structuredClone(good());
  fn(doc);
  return validateEnvelope(doc);
};
const rulesOf = (r) => r.errors.map((e) => e.rule);

describe("the stack really returns the verdicts these tests rely on", () => {
  test("allow, escalate, deny", () => {
    assert.equal(judge(ALLOWED).decision, ALLOW);
    assert.equal(judge(OVER).decision, ESCALATE);
    assert.equal(judge(WRONG_ASSET).decision, DENY);
    assert.equal(judge(ALLOWED, { signatureValid: false }).code, "BAD_SIGNATURE");
  });

  test("the escalate codes used below", () => {
    assert.equal(judge(OVER).code, "OVER_PER_CALL");
    assert.equal(judge(quote(rlusd("0.04")), { spend: { total: rlusd("1.99"), window: 0n } }).code, "OVER_TOTAL");
    assert.equal(judge(quote(rlusd("0.04")), { spend: { total: 0n, window: rlusd("0.48") } }).code, "OVER_WINDOW");
    assert.equal(judge(ALLOWED, { channelCap: rlusd("0.005") }).code, "OVER_CHANNEL_CAP");
    assert.equal(judge(quote(rlusd("0.01"), { payTo: STRANGER })).code, "UNKNOWN_MERCHANT");
    assert.equal(judge(ALLOWED, { now: NOW + 7200 }).code, "MANDATE_EXPIRED");
  });
});

describe("makeEvent", () => {
  const base = { stage: "quote", outcome: "ok", actor: "merchant", summary: "402 challenge" };

  test("fills ts, in RFC 3339 UTC with a Z", () => {
    const e = makeEvent(base);
    assert.match(e.ts, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  });

  test("unix seconds and Dates become ts; a given string is kept", () => {
    assert.equal(makeEvent({ ...base, ts: NOW }).ts, TS);
    assert.equal(makeEvent({ ...base, ts: new Date(TS) }).ts, TS);
    assert.equal(makeEvent({ ...base, ts: "2026-10-28T12:00:00Z" }).ts, TS);
  });

  test("ts must be a string in the exact shape: an array holding a good one is refused", () => {
    for (const bad of [[TS], {}, true, "2026-10-28T12:00:00Z\n", "2026-10-28 12:00:00Z"])
      assert.throws(
        () => makeEvent({ ...base, ts: bad }),
        (e) => e instanceof AuditSchemaError && e.errors.some((x) => x.rule === "ts-format"),
        JSON.stringify(bad),
      );
    assert.throws(() => makeEvent({ ...base, ts: NaN }), RangeError);
  });

  test("each of the five required fields is checked (rule 1)", () => {
    for (const f of ["stage", "outcome", "actor", "summary"]) {
      const { [f]: _gone, ...rest } = base;
      assert.throws(
        () => makeEvent(rest),
        (e) => e instanceof AuditSchemaError && e.errors.some((x) => x.rule === 1 && x.message.includes(f)),
        f,
      );
    }
  });

  test("a number amount is refused; a bigint is written exactly", () => {
    assert.throws(
      () => makeEvent({ ...base, amount: 1000, unit: "drops" }),
      (e) => e.errors[0].rule === 5,
    );
    const e = makeEvent({ ...base, amount: 2n ** 70n, ceiling: 5n, unit: "drops" });
    assert.equal(e.amount, "1180591620717411303424");
    assert.equal(e.ceiling, "5");
  });

  test("unit and ceiling rules", () => {
    assert.throws(() => makeEvent({ ...base, amount: "1" }), (e) => e.errors.some((x) => x.rule === 6));
    assert.throws(() => makeEvent({ ...base, amount: "1", unit: "RLUSD" }), (e) => e.errors.some((x) => x.rule === 7));
    assert.throws(
      () => makeEvent({ ...base, ceiling: "5" }),
      (e) => e.errors.some((x) => x.rule === "ceiling-unit"),
    );
  });

  test("a summary is made one plain line with no trailing full stop (rule 4)", () => {
    assert.equal(makeEvent({ ...base, summary: "stopped." }).summary, "stopped");
    assert.equal(makeEvent({ ...base, summary: "  two   spaces\nand a line.  " }).summary, "two spaces and a line");
    // a full stop inside is kept
    assert.equal(makeEvent({ ...base, summary: "v1.2 quote" }).summary, "v1.2 quote");
  });

  test("control characters and Unicode spaces are removed before the full stop is looked for", () => {
    // U+001C-U+001F and U+0085 are the ones Python's strip() hides a stop behind
    for (const tail of [0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0x09, 0x7f, 0x9f, 0x2028, 0x2029, 0xa0, 0x3000, 0x200b, 0xfeff])
      assert.equal(makeEvent({ ...base, summary: `text.${ch(tail)}` }).summary, "text", tail.toString(16));
    assert.equal(makeEvent({ ...base, summary: `a${ch(0x1f)}b` }).summary, "a b");
    assert.equal(makeEvent({ ...base, summary: `a${ch(0x85)}b` }).summary, "a b");
    assert.equal(makeEvent({ ...base, summary: `text.${ch(0x1f)}  ${ch(0x85)}.` }).summary, "text");
  });

  test("a summary that is empty once cleaned, or is not a string, is refused", () => {
    for (const s of ["", "   ", ".", " . ", ch(0x1f), ch(0x85), `${ch(0x200b)}.`])
      assert.throws(
        () => makeEvent({ ...base, summary: s }),
        (e) => e.errors.some((x) => x.rule === "summary-empty"),
        JSON.stringify(s),
      );
    for (const s of [5, null, ["a"], {}, true])
      assert.throws(
        () => makeEvent({ ...base, summary: s }),
        (e) => e.errors.some((x) => x.rule === "summary-type"),
        JSON.stringify(s),
      );
  });

  test("cleanSummary: bounded by code points, ends with an ellipsis, no stop", () => {
    assert.equal(cleanSummary("short."), "short");
    const long = cleanSummary("x".repeat(500), 50);
    assert.equal([...long].length, 50);
    assert.ok(long.endsWith("\u2026"));
    // not cut through a surrogate pair
    assert.doesNotThrow(() => JSON.parse(JSON.stringify(cleanSummary("\u{1F600}".repeat(100), 21))));
    assert.equal([...cleanSummary("\u{1F600}".repeat(100), 21)].length, 21);
  });

  test("a refusal must say how it is known", () => {
    assert.throws(
      () => makeEvent({ ...base, outcome: "refused" }),
      (e) => e.errors.some((x) => x.rule === "evidence-required"),
    );
    assert.equal(makeEvent({ ...base, outcome: "refused", evidence: "measured" }).evidence, "measured");
  });

  test("a mistyped field or an unlisted stage is refused, not passed through", () => {
    assert.throws(() => makeEvent({ ...base, txHash: TX }), (e) => e.errors[0].rule === "unknown-field");
    assert.throws(() => makeEvent({ ...base, stage: "payment" }), (e) => e.errors.some((x) => x.rule === "stage-unknown"));
  });

  test("detail with a bigint is written as a string", () => {
    const e = makeEvent({ ...base, detail: { n: 7n } });
    assert.equal(JSON.stringify(e.detail), '{"n":"7"}');
  });

  test("a detail that is not JSON at all is dropped rather than thrown on", () => {
    assert.equal("detail" in makeEvent({ ...base, detail: () => 1 }), false);
  });
});

describe("envelope", () => {
  test("defaults to XRPL EVM Testnet, eip155:1449000, and passes validation", () => {
    const doc = good();
    assert.equal(doc.schema, "agent-audit/1");
    assert.equal(doc.network, "eip155:1449000");
    assert.equal(EVM_TESTNET_NETWORK, "eip155:1449000");
    assert.deepEqual(Object.keys(doc), ["schema", "run_id", "network", "events"]);
    assert.equal(validateEnvelope(doc).ok, true);
  });

  test("1440000 is mainnet and is refused, as a default and by name", () => {
    assert.deepEqual(MAINNET_NETWORKS, ["eip155:1440000"]);
    assert.throws(
      () => envelope({ run_id: "r", network: "eip155:1440000", events: events(ALLOWED) }),
      (e) => e.errors.some((x) => x.rule === "network-forbidden"),
    );
    const r = mutate((d) => (d.network = "eip155:1440000"));
    assert.deepEqual(rulesOf(r), ["network-forbidden"]);
    // a caller with a real mainnet run can say so
    const doc = structuredClone(good());
    doc.network = "eip155:1440000";
    assert.equal(validateEnvelope(doc, { forbidNetworks: [] }).ok, true);
  });

  test("the chain id is compared as a number, so padding and case do not get round the check", () => {
    for (const net of ["eip155:01440000", "eip155:0001440000"]) {
      assert.throws(
        () => envelope({ run_id: "r", network: net, events: events(ALLOWED) }),
        (e) => e.errors.some((x) => x.rule === "network-forbidden"),
        net,
      );
    }
    for (const net of [" EIP155:1440000 ", "eip155:01440000", "Eip155:1440000"])
      assert.deepEqual(rulesOf(mutate((d) => (d.network = net))), ["network-forbidden"], net);
    // 1449000 is not 1440000 however it is written
    assert.equal(mutate((d) => (d.network = "eip155:01449000")).ok, true);
  });

  test("an eip155 reference that is not plain decimal digits is refused (0x15f900 is 1440000)", () => {
    for (const net of ["eip155:0x15f900", "eip155:1_440_000", "eip155:", "eip155:-1", "eip155:1440000.0"])
      assert.ok(rulesOf(mutate((d) => (d.network = net))).includes("network-format"), net);
    assert.throws(
      () => envelope({ run_id: "r", network: "eip155:0x15f900", events: events(ALLOWED) }),
      (e) => e.errors.some((x) => x.rule === "network-format"),
    );
  });

  test("envelope() honours forbidNetworks: a mainnet run passes only when the caller says so", () => {
    const evs = events(ALLOWED);
    const doc = envelope({ run_id: "r", network: "eip155:1440000", events: evs, forbidNetworks: [] });
    assert.equal(doc.network, "eip155:1440000");
    // a caller's own list replaces the default, and is matched by chain id
    assert.throws(
      () => envelope({ run_id: "r", events: evs, forbidNetworks: ["eip155:01449000"] }),
      (e) => e.errors.some((x) => x.rule === "network-forbidden"),
    );
    assert.throws(() => envelope({ run_id: "r", events: evs, forbidNetworks: "eip155:1440000" }), TypeError);
    assert.throws(() => envelope({ run_id: "r", events: evs, forbidNetworks: [1440000] }), TypeError);
  });

  test("network must be CAIP-2; events must exist; run_id must exist", () => {
    assert.throws(() => envelope({ run_id: "r", network: "xrpl-testnet", events: events(ALLOWED) }), AuditSchemaError);
    assert.throws(() => envelope({ run_id: "r", events: [] }), (e) => e.errors.some((x) => x.rule === "envelope-field"));
    assert.throws(() => envelope({ events: events(ALLOWED) }), (e) => e.errors.some((x) => x.rule === "envelope-field"));
  });

  test("an invalid event inside is refused", () => {
    const bad = { ...events(ALLOWED)[0], summary: "ends with a stop." };
    assert.throws(() => envelope({ run_id: "r", events: [bad] }), (e) => e.errors.some((x) => x.rule === 4));
  });

  test("the input array is copied, not aliased", () => {
    const evs = events(ALLOWED);
    const doc = envelope({ run_id: "r", events: evs });
    evs.length = 0;
    assert.equal(doc.events.length, 2);
  });
});

describe("validateEnvelope: one mutation per rule, rejected for the right reason", () => {
  test("the good envelope has no errors and no warnings", () => {
    const r = validateEnvelope(good());
    assert.deepEqual(r, { ok: true, errors: [], warnings: [] });
  });

  test("rule 1: each required field, removed", () => {
    for (const f of ["ts", "stage", "outcome", "actor", "summary"]) {
      const r = mutate((d) => delete d.events[0][f]);
      assert.deepEqual(rulesOf(r), [1], f);
      assert.match(r.errors[0].message, new RegExp(f));
    }
  });

  test("rule 2: outcome outside ok, refused, unknown, error", () => {
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].outcome = "denied"))), [2]);
    for (const o of ["ok", "refused", "unknown", "error"]) {
      const r = mutate((d) => {
        d.events[0].outcome = o;
        d.events[0].evidence = "measured";
      });
      assert.equal(r.ok, true, o);
    }
  });

  test("rule 3: actor outside the seven", () => {
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].actor = "policy"))), [3]);
    for (const a of ["agent", "merchant", "facilitator", "device", "owner", "ledger", "credential"]) {
      const r = mutate((d) => (d.events[0].actor = a));
      assert.equal(r.errors.length, 0, a);
    }
  });

  test("rule 4: trailing full stop, and only that", () => {
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary += "."))), [4]);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary += ".  "))), [4]);
    // invisible characters after the stop do not hide it
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary += `.${ch(0x200b)}`))), [4]);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary += `.${ch(0xa0)}`))), [4]);
    // a full stop inside is fine
    assert.equal(mutate((d) => (d.events[0].summary = "v1.2 quote")).ok, true);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary = "  "))), ["summary-empty"]);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary = `${ch(0x200b)}`))), ["summary-empty"]);
  });

  test("a summary is one plain line: any control character or line separator is refused", () => {
    // 0x0a is the only one the Python reader rejects; the rest it reads as spaces
    for (const c of [0x0a, 0x0d, 0x09, 0x00, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x7f, 0x80, 0x85, 0x9f, 0x2028, 0x2029]) {
      assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary = `a${ch(c)}b`))), ["summary-control"], c.toString(16));
      assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary = `text.${ch(c)}`))), ["summary-control"], `stop then ${c.toString(16)}`);
    }
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary = "a\nb"))), ["summary-control"]);
  });

  test("a summary must be a string", () => {
    for (const s of [5, null, ["a"], { a: 1 }, true])
      assert.deepEqual(rulesOf(mutate((d) => (d.events[0].summary = s))), ["summary-type"], JSON.stringify(s));
  });

  test("rule 5: amount and ceiling are strings, never numbers", () => {
    assert.deepEqual(rulesOf(mutate((d) => (d.events[1].amount = 0.01))), [5]);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[1].ceiling = 0.05))), [5]);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[1].amount = null))), [5]);
    // a bigint is not a string either: it would not survive JSON.stringify
    assert.deepEqual(rulesOf(mutate((d) => (d.events[1].amount = 10n ** 30n))), [5]);
  });

  test("rule 6: amount requires unit", () => {
    const r = mutate((d) => delete d.events[1].unit);
    assert.deepEqual(rulesOf(r), [6]);
  });

  test("rule 7: unit is drops, XRP, usd_cents or USD", () => {
    assert.deepEqual(rulesOf(mutate((d) => (d.events[1].unit = "RLUSD"))), [7]);
    for (const u of ["drops", "XRP", "usd_cents", "USD"]) assert.equal(mutate((d) => (d.events[1].unit = u)).ok, true, u);
  });

  test("rule 8: replay_refused needs actor ledger, and a ledger one is allowed", () => {
    for (const actor of ["credential", "agent", "merchant", "facilitator", "device", "owner"]) {
      const r = mutate((d) => {
        d.events[0].stage = "replay_refused";
        d.events[0].actor = actor;
      });
      assert.deepEqual(rulesOf(r), [8], actor);
    }
    // the blanket ban would fail this; the actor-scoped rule must not
    const ok = mutate((d) => {
      d.events[0].stage = "replay_refused";
      d.events[0].actor = "ledger";
      d.events[0].outcome = "refused";
      d.events[0].evidence = "measured";
      d.events[0].tx_hash = TX;
      d.events[0].tx_result = "tecNO_ENTRY";
    });
    assert.deepEqual(ok, { ok: true, errors: [], warnings: [] });
  });

  test("a refused event with no evidence is rejected; a bad evidence value too", () => {
    const missing = mutate((d) => {
      d.events[0].outcome = "refused";
      delete d.events[0].evidence;
    });
    assert.deepEqual(rulesOf(missing), ["evidence-required"]);
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0].evidence = "certain"))), ["evidence-enum"]);
  });

  test("ts must be a string: RFC 3339 UTC with a Z", () => {
    for (const bad of ["2026-10-28 12:00:00Z", "2026-10-28T12:00:00+00:00", "2026-10-28T12:00:00", 1792000000]) {
      assert.deepEqual(rulesOf(mutate((d) => (d.events[0].ts = bad))), ["ts-format"], String(bad));
    }
    assert.equal(mutate((d) => (d.events[0].ts = "2026-10-28T12:00:00.250Z")).ok, true);
  });

  test("ts that only looks right to the Python reader: an array, a trailing newline, non-ASCII digits", () => {
    // Python str()-coerces, so a list holding a good timestamp passes there; its $ and \d also allow these two
    for (const bad of [[TS], { toString: () => TS }, `${TS}\n`, "2026-10-28T12:00:00Z".replace("12", "\u0661\u0662")])
      assert.deepEqual(rulesOf(mutate((d) => (d.events[0].ts = bad))), ["ts-format"], JSON.stringify(bad));
  });

  test("envelope: wrong schema, missing fields, events not a list, non-object event", () => {
    assert.deepEqual(rulesOf(mutate((d) => (d.schema = "agent-audit/2"))), ["envelope-schema"]);
    for (const f of ["run_id", "network", "events"])
      assert.ok(rulesOf(mutate((d) => delete d[f])).includes("envelope-field"), f);
    assert.deepEqual(rulesOf(mutate((d) => (d.events = []))), ["envelope-field"]);
    assert.ok(rulesOf(mutate((d) => (d.events = "nope"))).includes("events-not-list"));
    assert.deepEqual(rulesOf(mutate((d) => (d.events[0] = "x"))), ["event-not-object"]);
    assert.deepEqual(validateEnvelope(null).errors.map((e) => e.rule), ["envelope-not-object"]);
  });

  test("run_id and network must be non-empty strings, not just truthy values", () => {
    for (const f of ["run_id", "network"])
      for (const bad of [{}, [], ["x"], 5, true, "", null])
        assert.ok(rulesOf(mutate((d) => (d[f] = bad))).includes("envelope-field"), `${f}=${JSON.stringify(bad)}`);
    // a bad network value must not crash the mainnet check
    assert.doesNotThrow(() => validateEnvelope({ ...good(), network: {} }));
  });

  test("advisories: an unhashed ledger event, and events out of order, warn but do not fail", () => {
    const noHash = mutate((d) => (d.events[0].actor = "ledger"));
    assert.equal(noHash.ok, true);
    assert.deepEqual(noHash.warnings.map((w) => w.rule), ["ledger-no-tx-hash"]);
    const order = mutate((d) => (d.events[1].ts = "2026-10-28T11:00:00Z"));
    assert.equal(order.ok, true);
    assert.deepEqual(order.warnings.map((w) => w.rule), ["ts-order"]);
  });

  test("advisory: a tx_hash in neither chain-native form warns, and does not fail", () => {
    const withHash = (h) => mutate((d) => (d.events[0].tx_hash = h));
    // EVM: 0x and 64 hex (either case); XRPL: 64 uppercase hex
    for (const h of [TX, `0x${"AB".repeat(32)}`, "AB12".repeat(16)]) {
      assert.deepEqual(withHash(h), { ok: true, errors: [], warnings: [] }, h);
    }
    for (const h of ["ab".repeat(32), "0x123", `0x${"zz".repeat(32)}`, "", `${TX}0`, 5, null]) {
      const r = withHash(h);
      assert.equal(r.ok, true, String(h));
      assert.deepEqual(r.warnings.map((w) => w.rule), ["tx-hash-format"], String(h));
    }
  });

  test("several faults at once are all reported", () => {
    const r = mutate((d) => {
      d.events[1].amount = 5;
      d.events[1].unit = "RLUSD";
      d.events[0].actor = "bank";
    });
    assert.deepEqual(rulesOf(r).sort(), [3, 5, 7]);
  });
});

describe("verdictEvents: ALLOW", () => {
  const evs = events(ALLOWED);

  test("a quote from the merchant, then the Guard's check; nothing else", () => {
    assert.deepEqual(stages(evs), ["quote", "policy_check"]);
    assert.deepEqual(mix(evs), [
      ["quote", "merchant", "ok", "measured"],
      ["policy_check", "facilitator", "ok", "measured"],
    ]);
  });

  test("the quote is measured: the code decoded the challenge it was handed", () => {
    assert.equal(byStage(evs, "quote").evidence, "measured");
  });

  test("the Guard row says where it ran, and that it is not the model", () => {
    const d = byStage(evs, "policy_check").detail;
    assert.equal(d.enforcement_point, "in-process library inside the payer, reading an owner-signed mandate");
    assert.match(d.decided_by, /not the model/);
    assert.equal(d.decision, ALLOW);
  });

  test("the RLUSD amount is exact and says how it was converted", () => {
    const q = byStage(evs, "quote");
    assert.equal(q.amount, "0.01");
    assert.equal(q.unit, "USD");
    assert.equal(q.asset, "RLUSD");
    assert.equal(parseUnits(q.amount, 18), rlusd("0.01"));
    assert.match(q.detail.amount_basis, /RLUSD/);
    assert.match(q.detail.amount_basis, /18-decimal/);
    assert.match(q.detail.amount_basis, /exactly/);
    assert.equal(q.detail.amount_base_units, "10000000000000000");
  });

  test("the policy check carries the intent verbatim, and states the per-call ceiling", () => {
    const evs2 = verdictEvents({
      challenge: ALLOWED,
      verdict: judge(ALLOWED),
      mandateId,
      ts: TS,
      mandate,
      intent: "fetch 7-day volatility for the risk report",
    });
    const p = byStage(evs2, "policy_check");
    assert.equal(p.evidence, "measured");
    assert.equal(p.policy, "WITHIN_MANDATE");
    assert.equal(p.intent, "fetch 7-day volatility for the risk report");
    assert.equal(p.ceiling, "0.05");
    assert.equal(p.unit, "USD");
    assert.equal(p.detail.mandate_id, mandateId);
  });

  test("without the mandate there is no ceiling to state, so none is invented", () => {
    const p = byStage(verdictEvents({ challenge: ALLOWED, verdict: judge(ALLOWED), ts: TS }), "policy_check");
    assert.equal("ceiling" in p, false);
  });

  test("the quote and the check share one invoice_id, derived from the challenge", () => {
    const [q, p] = evs;
    assert.match(q.invoice_id, /^[0-9a-f]{64}$/);
    assert.equal(q.invoice_id, p.invoice_id);
    assert.equal(q.invoice_id, invoiceIdFor(structuredClone(ALLOWED)));
    assert.notEqual(q.invoice_id, invoiceIdFor(OVER));
  });

  test("no tx_hash, no settle, and no ledger actor anywhere", () => {
    assert.equal(evs.some((e) => e.stage === "settle" || e.actor === "ledger" || "tx_hash" in e), false);
  });
});

describe("verdictEvents: ESCALATE (a hold, not a refusal)", () => {
  const evs = events(OVER);

  test("the Guard's hold is ok and measured; nothing asks the device unless the caller says so", () => {
    assert.deepEqual(mix(evs), [
      ["quote", "merchant", "ok", "measured"],
      ["policy_check", "facilitator", "ok", "measured"],
    ]);
  });

  test("it says held for owner approval, keeps the word ESCALATE, and states the cap it crossed", () => {
    const p = byStage(evs, "policy_check");
    assert.match(p.summary, /held the payment for owner approval \(OVER_PER_CALL\)/);
    assert.equal(p.detail.decision, "ESCALATE");
    assert.equal(p.policy, "OVER_PER_CALL");
    assert.equal(p.amount, "0.4");
    assert.equal(p.ceiling, "0.05");
    assert.equal(p.detail.ceiling_kind, "maxPerCall");
  });

  test("approvalRequested false is the same as leaving it out", () => {
    assert.deepEqual(stages(events(OVER, { approvalRequested: false })), ["quote", "policy_check"]);
  });

  test("when the caller says the request was raised: a facilitator row, ok, measured, nothing about a screen", () => {
    const withAsk = events(OVER, { approvalRequested: true });
    assert.deepEqual(stages(withAsk), ["quote", "policy_check", "device_prompt"]);
    assert.deepEqual(mix(withAsk).at(-1), ["device_prompt", "facilitator", "ok", "measured"]);
    const d = byStage(withAsk, "device_prompt");
    assert.equal(d.summary, "payer asked the owner to approve this one payment; what a device screen showed is not observed");
    assert.match(d.detail.observed, /not observed/);
    assert.match(d.detail.source, /caller stated/);
    assert.equal(d.detail.grant_can_clear, true);
    assert.equal(d.amount, "0.4");
    assert.doesNotMatch(JSON.stringify(d), /screens/);
  });

  test("approvalRequested only makes sense for a hold", () => {
    assert.throws(() => events(ALLOWED, { approvalRequested: true }), TypeError);
    assert.throws(() => events(WRONG_ASSET, { approvalRequested: true }), TypeError);
    // false is harmless anywhere; anything but a boolean is a caller bug
    assert.doesNotThrow(() => events(ALLOWED, { approvalRequested: false }));
    for (const bad of ["yes", 1, null, {}]) assert.throws(() => events(OVER, { approvalRequested: bad }), TypeError, String(bad));
  });

  test("a prompt option from the old API is refused, not ignored", () => {
    assert.throws(() => events(OVER, { promptShown: true }), /unknown option/);
    assert.throws(() => events(OVER, { screens: ["a"] }), /unknown option/);
  });
});

describe("verdictEvents: what a grant can and cannot answer", () => {
  const asked = (challenge, o = {}) => events(challenge, { approvalRequested: true }, o);
  const prompt = (evs) => byStage(evs, "device_prompt");

  test("over per-call, over total, over window: a one-payment grant answers these", () => {
    const cases = [
      asked(OVER),
      asked(quote(rlusd("0.04")), { spend: { total: rlusd("1.99"), window: 0n } }),
      asked(quote(rlusd("0.04")), { spend: { total: 0n, window: rlusd("0.48") } }),
    ];
    assert.deepEqual(
      cases.map((evs) => byStage(evs, "policy_check").policy),
      ["OVER_PER_CALL", "OVER_TOTAL", "OVER_WINDOW"],
    );
    for (const evs of cases) {
      assert.match(prompt(evs).summary, /^payer asked the owner to approve this one payment;/);
      assert.equal(prompt(evs).detail.grant_can_clear, true);
      assert.equal("resolved_by" in prompt(evs).detail, false);
    }
  });

  test("an unknown payee and an expired mandate are not cleared by a grant; only a new mandate resolves them", () => {
    for (const [evs, code] of [
      [asked(quote(rlusd("0.01"), { payTo: STRANGER })), "UNKNOWN_MERCHANT"],
      [asked(ALLOWED, { now: NOW + 7200 }), "MANDATE_EXPIRED"],
    ]) {
      assert.equal(byStage(evs, "policy_check").policy, code);
      const d = prompt(evs);
      assert.equal(d.summary, `payer asked the owner to act on ${code}; a one-payment grant does not clear this; what a device screen showed is not observed`);
      assert.doesNotMatch(d.summary, /approve this one payment/);
      assert.equal(d.detail.grant_can_clear, false);
      assert.equal(d.detail.resolved_by, "a new signed mandate");
    }
  });

  test("the channel cap is not cleared by a grant either, and nothing is claimed about what does", () => {
    const evs = asked(ALLOWED, { channelCap: rlusd("0.005") });
    assert.equal(byStage(evs, "policy_check").policy, "OVER_CHANNEL_CAP");
    const d = prompt(evs);
    assert.match(d.summary, /a one-payment grant does not clear this/);
    assert.equal(d.detail.grant_can_clear, false);
    assert.equal("resolved_by" in d.detail, false);
  });

  test("no row anywhere says a grant would clear an unknown payee or an expired mandate", () => {
    for (const evs of [
      asked(quote(rlusd("0.01"), { payTo: STRANGER })),
      asked(ALLOWED, { now: NOW + 7200 }),
    ])
      assert.doesNotMatch(evs.map((e) => e.summary).join("\n"), /grant(?! does not clear)/i);
  });
});

describe("verdictEvents: DENY", () => {
  test("a wrong asset is a measured refusal by the Guard; no device prompt; no amount (it cannot be converted exactly)", () => {
    const evs = events(WRONG_ASSET);
    assert.deepEqual(stages(evs), ["quote", "policy_check"]);
    assert.deepEqual(mix(evs), [
      ["quote", "merchant", "ok", "measured"],
      ["policy_check", "facilitator", "refused", "measured"],
    ]);
    const p = byStage(evs, "policy_check");
    assert.equal(p.policy, "ASSET_MISMATCH");
    assert.equal(p.detail.decision, "DENY");
    for (const e of evs) {
      assert.equal("amount" in e, false);
      assert.equal("unit" in e, false);
    }
    // the figure is still kept, as the merchant wrote it, in the unrendered detail
    assert.equal(byStage(evs, "quote").detail.amount_raw, "10000000000000000");
    assert.equal(byStage(evs, "quote").detail.asset_address, OTHER_TOKEN);
  });

  test("a refusal before any request (revoked) has a check and no quote", () => {
    const verdict = { decision: DENY, code: "REVOKED", detail: { mandateId }, message: "mandate has been revoked" };
    const evs = verdictEvents({ verdict, mandateId, ts: TS });
    assert.deepEqual(stages(evs), ["policy_check"]);
    assert.equal(evs[0].outcome, "refused");
    assert.equal(evs[0].evidence, "measured");
    assert.equal(evs[0].actor, "facilitator");
  });

  test("several options in one 402: no amount is stated", () => {
    const two = { resource: ALLOWED.resource, accepts: [ALLOWED.accepts[0], ALLOWED.accepts[0]] };
    const evs = events(two);
    assert.equal(byStage(evs, "policy_check").policy, "MULTIPLE_ACCEPTS");
    assert.equal(evs.some((e) => "amount" in e), false);
  });

  test("an amount that is not plain digits is not converted", () => {
    for (const odd of ["0x10", " 5", "1e18", "-1", "1.5", ""]) {
      const evs = verdictEvents({
        challenge: quote(odd),
        verdict: { decision: DENY, code: "MALFORMED_CHALLENGE", detail: {}, message: "unreadable amount" },
        ts: TS,
      });
      assert.equal(evs.some((e) => "amount" in e), false, JSON.stringify(odd));
    }
  });
});

describe("verdictEvents: exact conversion", () => {
  test("one base unit and a 30-digit figure convert without rounding", () => {
    const one = byStage(events(quote("1")), "quote");
    assert.equal(one.amount, "0.000000000000000001");
    const big = 123456789012345678901234567890n;
    const e = byStage(
      verdictEvents({
        challenge: quote(big),
        verdict: { decision: DENY, code: "MALFORMED_CHALLENGE", detail: {}, message: "x" },
        ts: TS,
      }),
      "quote",
    );
    assert.equal(e.amount, "123456789012.34567890123456789");
    assert.equal(parseUnits(e.amount, 18), big);
    assert.equal(typeof e.amount, "string");
  });

  test("the asset comparison ignores case", () => {
    assert.equal(byStage(events(quote(rlusd("0.01"), { asset: RLUSD.toLowerCase() })), "quote").amount, "0.01");
  });
});

describe("verdictEvents: grant answers and where the approver key lives", () => {
  const GRANT_BASE = quote(rlusd("0.2"));
  const GRANTED = { decision: ALLOW, code: "WITHIN_GRANT", detail: {}, message: "m" };
  const withGrant = (grantAnswer, o = {}) =>
    verdictEvents({ challenge: GRANT_BASE, verdict: GRANTED, ts: TS, grantAnswer, ...o });
  const SIGNED = { status: "signed", signatureValid: true, grantId: "0xg", approver: approver.address };

  test("the signer constants are the strings the gate side uses", () => {
    assert.deepEqual([SOFTWARE_SIGNER, EMULATOR_SIGNER, DEVICE_SIGNER], ["software-key-standin", "ledger-emulator", "ledger-device"]);
    assert.deepEqual([...SIGNERS], [SOFTWARE_SIGNER, EMULATOR_SIGNER, DEVICE_SIGNER]);
  });

  test("signer left out: a valid signature implies the owner approved, and where the key lives is not stated", () => {
    const d = byStage(withGrant(SIGNED), "device_decision");
    assert.equal(d.actor, "owner");
    assert.equal(d.outcome, "ok");
    assert.equal(d.evidence, "inferred");
    assert.match(d.summary, /implies the owner approved; where the key lives is not stated$/);
    assert.match(d.detail.not_observed, /not watched/);
    assert.match(d.detail.basis, /where that key lives is not stated/);
    assert.equal("signer" in d.detail, false);
  });

  test("ledger-device: the key lives on the device, so a press is inferred", () => {
    const d = byStage(withGrant(SIGNED, { signer: DEVICE_SIGNER }), "device_decision");
    assert.deepEqual([d.actor, d.outcome, d.evidence], ["owner", "ok", "inferred"]);
    assert.equal(d.summary, "a valid signature from the registered approver key arrived, which implies the owner approved on the device");
    assert.match(d.detail.basis, /the key lives on the device, so a press is inferred, not observed/);
    assert.equal(d.detail.signer, DEVICE_SIGNER);
    assert.equal(d.detail.grant_id, "0xg");
  });

  test("ledger-emulator: the key is in Speculos and no physical device was involved", () => {
    const d = byStage(withGrant(SIGNED, { signer: EMULATOR_SIGNER }), "device_decision");
    assert.deepEqual([d.actor, d.outcome, d.evidence], ["owner", "ok", "inferred"]);
    assert.match(d.summary, /implies the owner approved in the Speculos emulator; the key is in the emulator and no physical device was involved$/);
    assert.doesNotMatch(d.summary, /on the device/);
    assert.match(d.detail.basis, /no physical device was involved/);
    assert.equal(d.detail.signer, EMULATOR_SIGNER);
  });

  test("software stand-in: nobody pressed anything, so there is no device_decision row at all", () => {
    const evs = withGrant(SIGNED, { signer: SOFTWARE_SIGNER });
    assert.deepEqual(stages(evs), ["quote", "policy_check"]);
    const p = byStage(evs, "policy_check");
    assert.equal(p.detail.signer, SOFTWARE_SIGNER);
    assert.match(p.detail.basis, /software key held by a script; no hardware device signed and no button was pressed/);
    assert.equal(p.outcome, "ok");
  });

  test("the other signers put their value on the row that used the grant, with no software basis", () => {
    for (const signer of [DEVICE_SIGNER, EMULATOR_SIGNER]) {
      const p = byStage(withGrant(SIGNED, { signer }), "policy_check");
      assert.equal(p.detail.signer, signer);
      assert.equal("basis" in p.detail, false);
    }
    // a verdict that did not rely on a grant carries no signer
    assert.equal("signer" in byStage(events(ALLOWED, { signer: DEVICE_SIGNER }), "policy_check").detail, false);
  });

  test("any other signer value throws, whatever the verdict", () => {
    for (const bad of ["ledger", "hardware", "LEDGER-DEVICE", "", null, 5, {}, true])
      assert.throws(() => withGrant(SIGNED, { signer: bad }), TypeError, JSON.stringify(bad));
    assert.throws(() => events(ALLOWED, { signer: "nope" }), /signer must be one of/);
  });

  test("the Guard's own message about a human on the device is not copied into the summary", () => {
    const evs = verdictEvents({
      challenge: ALLOWED,
      verdict: { decision: ALLOW, code: "WITHIN_GRANT", detail: {}, message: "a human granted this one payment on the device" },
      ts: TS,
    });
    assert.doesNotMatch(byStage(evs, "policy_check").summary, /human|device/);
  });

  test("an invalid signature is not an owner decision, so no device_decision is emitted, for any signer", () => {
    for (const signer of [undefined, ...SIGNERS]) {
      const evs = verdictEvents({
        challenge: GRANT_BASE,
        verdict: judge(GRANT_BASE, { grant: { message: {} }, grantSignatureValid: false }),
        ts: TS,
        grantAnswer: { status: "signed", signatureValid: false },
        signer,
      });
      assert.equal(byStage(evs, "policy_check").policy, "BAD_GRANT_SIGNATURE");
      assert.equal(stages(evs).includes("device_decision"), false);
    }
  });

  test("a rejection the signer reported: the owner refused, inferred, because nothing here authenticates who pressed it", () => {
    for (const signer of [undefined, ...SIGNERS]) {
      const d = byStage(withGrant({ status: "rejected" }, { signer }), "device_decision");
      assert.deepEqual([d.actor, d.outcome, d.evidence], ["owner", "refused", "inferred"], String(signer));
      assert.match(d.detail.basis, /nothing here authenticates who pressed it/);
      assert.equal(d.detail.signer, signer);
    }
    const soft = byStage(withGrant({ status: "rejected" }, { signer: SOFTWARE_SIGNER }), "device_decision");
    assert.match(soft.summary, /software key stands in for the device/);
    assert.match(soft.detail.stand_in, /no button was pressed/);
  });

  test("a signer error is an error the payer saw, not a refusal by the owner and not a claim about the device", () => {
    const d = byStage(withGrant({ status: "error", error: "transport closed\nbefore reply." }), "device_decision");
    assert.deepEqual([d.actor, d.outcome, d.evidence], ["facilitator", "error", "measured"]);
    assert.equal(d.detail.error, "transport closed before reply");
    assert.doesNotMatch(d.summary, /device/);
  });

  test("a grant answer with another status is a caller bug", () => {
    for (const status of ["approved", "SIGNED", undefined, null])
      assert.throws(() => withGrant({ status }), TypeError, String(status));
  });

  test("events come back oldest first, even when the answer predates the quote", () => {
    const evs = withGrant({ ...SIGNED, ts: "2026-10-28T11:59:30Z" });
    assert.deepEqual(stages(evs), ["device_decision", "quote", "policy_check"]);
    assert.equal(validateEnvelope({ schema: "agent-audit/1", run_id: "r", network: EVM_TESTNET_NETWORK, events: evs }).warnings.length, 0);
  });
});

describe("verdictEvents: settle", () => {
  const settle = (settlement) => verdictEvents({ challenge: ALLOWED, verdict: judge(ALLOWED), ts: TS, settlement });

  test("no tx hash, no settle event", () => {
    assert.equal(stages(settle(undefined)).includes("settle"), false);
    assert.equal(stages(settle({})).includes("settle"), false);
    assert.equal(stages(settle({ txHash: null })).includes("settle"), false);
  });

  test("a hash from the merchant's header is the merchant's claim, labelled inferred and unverified", () => {
    const s = byStage(settle({ txHash: TX }), "settle");
    assert.equal(s.actor, "merchant");
    assert.equal(s.evidence, "inferred");
    assert.equal(s.tx_hash, TX);
    assert.equal(s.detail.verified_on_chain, false);
    assert.match(s.summary, /not checked on chain/);
    assert.equal("explorer_url" in s, false);
  });

  test("a receipt read from chain makes it the ledger's, measured", () => {
    const s = byStage(settle({ txHash: TX, chainReceipt: { status: 1, blockNumber: 9229025 }, explorerUrl: "https://explorer.example/tx/1" }), "settle");
    assert.equal(s.actor, "ledger");
    assert.equal(s.outcome, "ok");
    assert.equal(s.evidence, "measured");
    assert.equal(s.explorer_url, "https://explorer.example/tx/1");
    assert.equal(s.detail.verified_on_chain, true);
    assert.equal(s.detail.block_number, "9229025");
  });

  test("a reverted receipt is an error, not a settlement", () => {
    const s = byStage(settle({ txHash: TX, chainReceipt: { status: 0 } }), "settle");
    assert.equal(s.outcome, "error");
    assert.equal(s.detail.verified_on_chain, false);
  });

  test("the settle row names who was paid: detail.destination is the quote's payTo, for the merchant's claim and for a chain receipt", () => {
    assert.equal(byStage(settle({ txHash: TX }), "settle").detail.destination, MERCHANT);
    assert.equal(byStage(settle({ txHash: TX, chainReceipt: { status: 1 } }), "settle").detail.destination, MERCHANT);
    assert.equal(byStage(settle({ txHash: TX, chainReceipt: { status: 0 } }), "settle").detail.destination, MERCHANT);
  });

  test("no destination is written when the quote does not name one payee (several options, or an empty payTo)", () => {
    const two = { resource: ALLOWED.resource, accepts: [ALLOWED.accepts[0], ALLOWED.accepts[0]] };
    const noPayee = quote(rlusd("0.01"), { payTo: "" });
    for (const c of [two, noPayee]) {
      const s = byStage(verdictEvents({ challenge: c, verdict: judge(ALLOWED), ts: TS, settlement: { txHash: TX } }), "settle");
      assert.equal("destination" in s.detail, false);
    }
  });

  test("the hash is written in the EVM form, 0x and lowercase hex, and passes the advisory check", () => {
    const upper = `0x${"AB".repeat(32)}`;
    const s = byStage(settle({ txHash: upper }), "settle");
    assert.equal(s.tx_hash, TX);
    const r = validateEnvelope({ schema: "agent-audit/1", run_id: "r", network: EVM_TESTNET_NETWORK, events: [s] });
    assert.deepEqual(r, { ok: true, errors: [], warnings: [] });
  });

  test("a malformed hash throws rather than being written", () => {
    for (const bad of ["0x123", "AB".repeat(32), `0x${"zz".repeat(32)}`, 5])
      assert.throws(() => settle({ txHash: bad }), TypeError, String(bad));
  });

  test("a settlement for a verdict that did not allow payment is a caller bug", () => {
    assert.throws(
      () => verdictEvents({ challenge: OVER, verdict: judge(OVER), ts: TS, settlement: { txHash: TX } }),
      TypeError,
    );
  });
});

describe("verdictEvents: hostile and malformed input", () => {
  const valid = (evs) => validateEnvelope({ schema: "agent-audit/1", run_id: "r", network: EVM_TESTNET_NETWORK, events: evs });

  test("a resource URL with a newline and a trailing full stop still gives a valid one-line summary", () => {
    const evs = events(quote(rlusd("0.01"), { url: "https://merchant.example/data\nINJECTED ROW." }));
    const q = byStage(evs, "quote");
    assert.doesNotMatch(q.summary, /\n/);
    assert.doesNotMatch(q.summary, /\.$/);
    assert.equal(valid(evs).ok, true);
  });

  test("control characters the Python reader mistakes for spaces cannot hide a stop or break the row", () => {
    for (const c of [0x1c, 0x1f, 0x85, 0x2028, 0x200b, 0xfeff]) {
      const evs = events(quote(rlusd("0.01"), { url: `https://merchant.example/data.${ch(c)}` }));
      const q = byStage(evs, "quote");
      assert.doesNotMatch(q.summary, /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/, c.toString(16));
      assert.doesNotMatch(q.summary, /\.$/, c.toString(16));
      assert.deepEqual(valid(evs), { ok: true, errors: [], warnings: [] }, c.toString(16));
    }
  });

  test("a hostile Guard message goes through the same cleaning", () => {
    const verdict = { decision: DENY, code: "MALFORMED_CHALLENGE", detail: {}, message: `bad${ch(0x1f)}row.${ch(0x85)}` };
    const evs = verdictEvents({ challenge: ALLOWED, verdict, ts: TS });
    assert.equal(byStage(evs, "policy_check").summary, "Guard denied the payment (MALFORMED_CHALLENGE): bad row");
    assert.equal(valid(evs).ok, true);
  });

  test("a very long resource URL is cut, not stored whole in the summary", () => {
    const q = byStage(events(quote(rlusd("0.01"), { url: `https://merchant.example/${"a".repeat(5000)}` })), "quote");
    assert.ok(q.summary.length <= 220, String(q.summary.length));
  });

  test("an oversized verdict detail is replaced by a marker, and the event is still valid", () => {
    const verdict = { decision: DENY, code: "MALFORMED_CHALLENGE", detail: { challenge: "x".repeat(50_000) }, message: "bad" };
    const p = byStage(verdictEvents({ challenge: ALLOWED, verdict, ts: TS }), "policy_check");
    assert.equal(p.detail.truncated, true);
    assert.ok(p.detail.original_json_chars > 50_000);
  });

  test("bigints in verdict detail serialise", () => {
    const evs = events(OVER);
    assert.doesNotThrow(() => JSON.stringify(evs));
    assert.equal(byStage(evs, "policy_check").detail.verdict_detail.maxPerCall, "50000000000000000");
  });

  test("a verdict that is not ALLOW, ESCALATE or DENY is refused", () => {
    assert.throws(() => verdictEvents({ verdict: { decision: "MAYBE" } }), TypeError);
    assert.throws(() => verdictEvents({}), TypeError);
  });

  test("a payer-style refusal with no challenge at all still validates", () => {
    const verdict = { decision: DENY, code: "REVOCATION_UNKNOWN", detail: { source: "never-read" }, message: "never read the registry — refusing to spend" };
    const doc = envelope({ run_id: "r", events: verdictEvents({ verdict, ts: TS }) });
    assert.equal(doc.events[0].policy, "REVOCATION_UNKNOWN");
  });
});

describe("a whole run through the real stack", () => {
  test("allow, hold, deny, then a grant that settles with a receipt, all in one valid envelope", () => {
    const grantBase = quote(rlusd("0.2"));
    const evs = [
      ...events(ALLOWED),
      ...events(OVER, { approvalRequested: true }),
      ...events(WRONG_ASSET),
      ...verdictEvents({
        challenge: grantBase,
        verdict: { decision: ALLOW, code: "WITHIN_GRANT", detail: { amount: rlusd("0.2") }, message: "granted" },
        mandateId,
        ts: "2026-10-28T12:01:00Z",
        grantAnswer: { status: "signed", signatureValid: true, ts: "2026-10-28T12:00:50Z" },
        signer: DEVICE_SIGNER,
        settlement: { txHash: TX, chainReceipt: { status: 1 } },
      }),
    ].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
    const doc = envelope({ run_id: makeRunId("run", TS), events: evs });
    const r = validateEnvelope(doc);
    assert.deepEqual(r, { ok: true, errors: [], warnings: [] });
    // exactly one refusal: the Guard's DENY. The hold is ok, and the Guard is the facilitator row.
    const refused = doc.events.filter((e) => e.outcome === "refused");
    assert.deepEqual(refused.map((e) => [e.stage, e.actor, e.evidence, e.policy]), [["policy_check", "facilitator", "measured", "ASSET_MISMATCH"]]);
    const guardRows = doc.events.filter((e) => e.stage === "policy_check");
    assert.equal(guardRows.length, 4);
    assert.ok(guardRows.every((e) => e.actor === "facilitator" && e.evidence === "measured"));
    assert.deepEqual(guardRows.map((e) => e.outcome), ["ok", "ok", "refused", "ok"]);
    // the only device_decision is the inferred one, by the owner
    assert.deepEqual(doc.events.filter((e) => e.stage === "device_decision").map((e) => [e.actor, e.outcome, e.evidence]), [["owner", "ok", "inferred"]]);
    // only the one event with a real receipt names the ledger
    assert.deepEqual(doc.events.filter((e) => e.actor === "ledger").map((e) => e.stage), ["settle"]);
    // nothing is a JSON number where the schema wants a string
    for (const e of doc.events) for (const f of ["amount", "ceiling"]) if (f in e) assert.equal(typeof e[f], "string");
    // and the document round-trips through JSON unchanged
    assert.deepEqual(JSON.parse(JSON.stringify(doc)), doc);
  });
});
