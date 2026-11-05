// The agent-audit/1 rules, as code. Pure: no I/O, no clock.
//
// A Python reference validator also exists. It is not in this repository.
//
// THE INVARIANT: whatever this validator accepts, `py -I validate-agent-audit.py`
// also accepts (a Python crash counts as a reject, since a shell reader sees a
// non-zero exit either way). It is NOT "accepts and rejects exactly the same":
// this one is deliberately stricter in the places tagged STRICTER below, so a
// file that passes here is safe to hand to the Python reader. The reverse does
// not hold, and nothing here relies on it.
//
// Each error carries a `rule` so a test can check a bad envelope was rejected
// for the right reason, not just rejected. The eight numbered rules:
//
//   1  every event has ts, stage, outcome, actor, summary
//   2  outcome is ok | refused | unknown | error
//   3  actor is one of the seven
//   4  summary has no trailing full stop
//   5  amount and ceiling are strings, never numbers
//   6  amount requires unit
//   7  unit is drops | XRP | usd_cents | USD
//   8  stage replay_refused requires actor ledger
//
// The Python file also enforces a few things the numbered list leaves implicit;
// they get string rule names: ts-format, evidence-required, evidence-enum,
// summary-empty, and the envelope checks. Checks that exist only here:
//
//   STRICTER ts            must be a JSON string (Python str()-coerces, so an
//                          array holding a good timestamp passes there), ASCII
//                          digits only, no trailing newline (Python's $ and \d
//                          allow both).
//   STRICTER summary       must be a string; no control character (C0, DEL, C1)
//                          and no line or paragraph separator. Python rejects
//                          only "\n" and treats U+001C-U+001F and U+0085 as
//                          whitespace, which hides a trailing full stop from
//                          the rule-4 test on this side.
//   STRICTER summary tail  invisible format characters (zero-width space, BOM)
//                          are ignored when looking for a trailing full stop or
//                          an empty summary; Python does not strip them.
//   STRICTER envelope      run_id and network must be non-empty strings (Python
//                          accepts any truthy value, a number or a list).
//   NEW      network       eip155:1440000 (XRPL EVM mainnet) is refused, by its
//                          numeric chain id, so eip155:01440000 is caught too.
//                          eip155 references must be plain decimal digits.
//   advisory tx_hash       a tx_hash that is neither 0x plus 64 hex nor 64
//                          uppercase hex warns.

export const SCHEMA = "agent-audit/1";

export const OUTCOMES = Object.freeze(["ok", "refused", "unknown", "error"]);
export const ACTORS = Object.freeze([
  "agent",
  "merchant",
  "facilitator",
  "device",
  "owner",
  "ledger",
  "credential",
]);
export const UNITS = Object.freeze(["drops", "XRP", "usd_cents", "USD"]);
export const EVIDENCE = Object.freeze(["measured", "inferred"]);
export const REQUIRED_FIELDS = Object.freeze(["ts", "stage", "outcome", "actor", "summary"]);

/** The agent-audit/1 stage list. The validator does not reject others (the Python one does not); makeEvent does. */
export const STAGES = Object.freeze([
  "quote",
  "policy_check",
  "authorize",
  "device_prompt",
  "device_decision",
  "settle",
  "reconcile",
  "deliver",
  "credential_verify",
  "constraint_check",
  "replay_attempt",
  "check_create",
  "check_cash",
  "replay_refused",
]);

/** Every field an event may carry. makeEvent rejects anything else, to catch typos. */
export const EVENT_FIELDS = Object.freeze([
  ...REQUIRED_FIELDS,
  "amount",
  "ceiling",
  "unit",
  "asset",
  "invoice_id",
  "tx_hash",
  "tx_result",
  "explorer_url",
  "intent",
  "policy",
  "evidence",
  "detail",
]);

/**
 * 1440000 is XRPL EVM MAINNET. This project runs on testnet (1449000), and an
 * envelope that said 1440000 would claim, inside an audit artifact, that money
 * moved on mainnet. The Python validator does not check
 * this; we do. A caller with a real mainnet run passes its own list, to
 * validateEnvelope() or to envelope() as `forbidNetworks`.
 */
export const MAINNET_NETWORKS = Object.freeze(["eip155:1440000"]);

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// STRICTER than Python: ASCII \d, and $ does not match before a trailing newline.
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
// C0, DEL and C1 controls, plus the line and paragraph separators (U+2028, U+2029).
const LINE_BREAKING = /[\p{Cc}\p{Zl}\p{Zp}]/u;
// What can trail a summary without being visible: Unicode spaces and format characters.
const INVISIBLE_TAIL = /[\s\p{Cf}]+$/u;
const TX_HASH_FORMS = /^(?:0x[0-9a-fA-F]{64}|[0-9A-F]{64})$/;
const EIP155_STRICT = /^eip155:(\d+)$/;

export class AuditSchemaError extends Error {
  /** @param {string} message @param {Array<{rule:(number|string), path:string, message:string}>} errors */
  constructor(message, errors = []) {
    super(message);
    this.name = "AuditSchemaError";
    this.errors = errors;
  }
}

/**
 * Make text fit `summary`: one line, no control characters, no trailing full
 * stop. Control characters and Unicode spaces are removed BEFORE the stop is
 * stripped, so "text.\u001f" and "text.  " do not keep their stop.
 * Used by makeEvent and by everything that builds a summary from outside text.
 *
 * @param {*} s
 * @param {number} [max] cut to this many characters (code points) and end with an ellipsis
 */
export function cleanSummary(s, max = Infinity) {
  let t = String(s).replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, " ").replace(/\s+/g, " ").trim();
  const points = [...t];
  if (points.length > max) t = `${points.slice(0, max - 1).join("").trimEnd()}…`;
  return t.replace(/[.\s\p{Cf}]+$/u, "");
}

/** CAIP-2 `eip155:<digits>` as a bigint chain id, or null if the text is not exactly that form. */
export function eip155ChainId(network) {
  const m = typeof network === "string" ? EIP155_STRICT.exec(network) : null;
  return m ? BigInt(m[1]) : null;
}

/** Forbidden by exact text or, for eip155, by numeric chain id; case and padding are ignored. */
function isForbiddenNetwork(network, forbid) {
  const forms = [network, network.trim().toLowerCase()];
  for (const form of forms) {
    const id = eip155ChainId(form);
    for (const f of forbid) {
      if (f === form) return true;
      const fid = eip155ChainId(f);
      if (id !== null && fid !== null && id === fid) return true;
    }
  }
  return false;
}

/**
 * Check one event. Returns { errors, warnings }, each entry { rule, path, message }.
 * @param {*} e
 * @param {string} at  label for messages, e.g. "event[3]"
 */
export function checkEvent(e, at = "event") {
  const errors = [];
  const warnings = [];
  const err = (rule, message) => errors.push({ rule, path: at, message });

  if (e === null || typeof e !== "object" || Array.isArray(e)) {
    err("event-not-object", "not an object");
    return { errors, warnings };
  }

  // Rule 1. Without all five the other checks have nothing to stand on.
  for (const f of REQUIRED_FIELDS) if (!has(e, f)) err(1, `missing required field ${f}`);
  if (REQUIRED_FIELDS.some((f) => !has(e, f))) return { errors, warnings };

  // STRICTER: a string, in the exact shape (see the header).
  if (typeof e.ts !== "string" || !TS.test(e.ts))
    err("ts-format", `ts ${JSON.stringify(e.ts)} is not an RFC 3339 UTC string ending in Z`);
  if (!OUTCOMES.includes(e.outcome))
    err(2, `outcome ${JSON.stringify(e.outcome)} not one of ${OUTCOMES.join(", ")}`);
  if (!ACTORS.includes(e.actor))
    err(3, `actor ${JSON.stringify(e.actor)} not one of ${ACTORS.join(", ")}`);

  // Rule 4, plus the summary checks the Python file makes beside it.
  if (typeof e.summary !== "string") {
    err("summary-type", `summary must be a string, got ${e.summary === null ? "null" : typeof e.summary}`);
  } else if (LINE_BREAKING.test(e.summary)) {
    // STRICTER: Python rejects only "\n", and strips U+001C-U+001F and U+0085 as whitespace.
    err("summary-control", "summary holds a control character or line separator; it must be one plain line");
  } else {
    // STRICTER: invisible trailing characters are ignored here, not only spaces.
    const visible = e.summary.replace(INVISIBLE_TAIL, "");
    if (!visible.trim()) err("summary-empty", "summary is empty");
    else if (visible.endsWith(".")) err(4, `summary ends with a full stop: ${JSON.stringify(e.summary)}`);
  }

  // Rule 8 is scoped to the actor. The blanket form ("no event may carry
  // replay_refused") would forbid the ledger event that is the point of the
  // replay beat, so this must stay an actor test.
  if (e.stage === "replay_refused" && e.actor !== "ledger")
    err(
      8,
      `stage 'replay_refused' with actor ${JSON.stringify(e.actor)}; only the ledger refuses a replay`,
    );

  // A refusal is a claim about who stopped what, so it must say how it is known.
  if (e.outcome === "refused" && !has(e, "evidence"))
    err("evidence-required", "outcome 'refused' requires evidence ('measured' or 'inferred')");
  if (has(e, "evidence") && !EVIDENCE.includes(e.evidence))
    err("evidence-enum", `evidence ${JSON.stringify(e.evidence)} not one of ${EVIDENCE.join(", ")}`);

  // Rules 5 to 7. An unlabelled or float amount is the bug the first draft had.
  for (const f of ["amount", "ceiling"])
    if (has(e, f) && typeof e[f] !== "string")
      err(5, `${f} must be a string, got ${e[f] === null ? "null" : typeof e[f]}`);
  if (has(e, "amount") && !has(e, "unit")) err(6, "amount given without unit");
  if (has(e, "unit") && !UNITS.includes(e.unit))
    err(7, `unit ${JSON.stringify(e.unit)} not one of ${UNITS.join(", ")}`);

  // Advisory, as in the Python file: the envelope's network groups events, it
  // does not prove any of them touched that chain. Only a tx_hash does.
  if (e.actor === "ledger" && !e.tx_hash)
    warnings.push({
      rule: "ledger-no-tx-hash",
      path: at,
      message: "ledger-actor event has no tx_hash, so nothing establishes it happened on the envelope's network",
    });

  // Advisory: keep the chain-native form (EVM 0x + hex; XRPL 64 uppercase hex). Not an error.
  if (has(e, "tx_hash") && !(typeof e.tx_hash === "string" && TX_HASH_FORMS.test(e.tx_hash)))
    warnings.push({
      rule: "tx-hash-format",
      path: at,
      message: "tx_hash is neither 0x plus 64 hex nor 64 uppercase hex",
    });

  if (has(e, "detail") && (e.detail === null || typeof e.detail !== "object" || Array.isArray(e.detail)))
    warnings.push({ rule: "detail-type", path: at, message: "detail should be an object" });

  return { errors, warnings };
}

/**
 * Check a whole envelope.
 *
 * @param {*} doc
 * @param {object} [opts]
 * @param {string[]} [opts.forbidNetworks] defaults to MAINNET_NETWORKS; pass [] to allow anything
 * @returns {{ok:boolean, errors:Array<{rule:(number|string), path:string, message:string}>, warnings:Array}}
 */
export function validateEnvelope(doc, { forbidNetworks = MAINNET_NETWORKS } = {}) {
  if (!Array.isArray(forbidNetworks) || forbidNetworks.some((n) => typeof n !== "string"))
    throw new TypeError("validateEnvelope: forbidNetworks must be an array of CAIP-2 strings");
  const errors = [];
  const warnings = [];
  const err = (rule, path, message) => errors.push({ rule, path, message });

  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    err("envelope-not-object", "envelope", "envelope is not an object");
    return { ok: false, errors, warnings };
  }

  if (doc.schema !== SCHEMA)
    err("envelope-schema", "envelope", `schema is ${JSON.stringify(doc.schema)}, expected ${JSON.stringify(SCHEMA)}`);

  // Python treats any falsy value as missing, so an empty events list counts as
  // missing there too. STRICTER: run_id and network must also be non-empty strings
  // (Python accepts a number, a list or a non-empty object).
  for (const f of ["run_id", "network"])
    if (typeof doc[f] !== "string" || !doc[f])
      err("envelope-field", "envelope", `envelope ${f} must be a non-empty string`);
  if (!doc.events || (Array.isArray(doc.events) && doc.events.length === 0))
    err("envelope-field", "envelope", "envelope missing events");

  if (typeof doc.network === "string" && doc.network) {
    // STRICTER: an eip155 reference is plain decimal digits (so 0x15f900 is not a way round the check).
    if (/^eip155:/i.test(doc.network.trim()) && eip155ChainId(doc.network.trim().toLowerCase()) === null)
      err("network-format", "envelope", `network ${JSON.stringify(doc.network)} is not eip155:<decimal digits>`);
    if (isForbiddenNetwork(doc.network, forbidNetworks))
      err(
        "network-forbidden",
        "envelope",
        `network ${doc.network} is not allowed here (1440000 is XRPL EVM mainnet; testnet is eip155:1449000)`,
      );
  }

  if (!Array.isArray(doc.events)) {
    if (doc.events) err("events-not-list", "envelope", "events is not a list");
    return { ok: errors.length === 0, errors, warnings };
  }

  let prev = null;
  doc.events.forEach((e, i) => {
    const r = checkEvent(e, `event[${i}]`);
    errors.push(...r.errors);
    warnings.push(...r.warnings);
    // Append-only, newest last. Advisory: equal ts is fine.
    const t = e && typeof e.ts === "string" ? Date.parse(e.ts) : NaN;
    if (!Number.isNaN(t)) {
      if (prev !== null && t < prev)
        warnings.push({ rule: "ts-order", path: `event[${i}]`, message: "ts is earlier than the event before it" });
      prev = t;
    }
  });

  return { ok: errors.length === 0, errors, warnings };
}
