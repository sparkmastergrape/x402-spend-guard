// Audit events: what the Guard already decides, written as agent-audit/1.
//
// This module is pure: no I/O,
// no network, no keys. It turns a decoded 402 challenge and a Guard verdict into
// events, and says only what the inputs support.
//
// Who is the actor, and how sure are we:
//   - The Guard is a library running inside the payer, reading a mandate the
//     owner signed. Every Guard row (allow, hold, deny) has actor `facilitator`
//     and evidence `measured`: the code returned that verdict. It is not the
//     model, and it is not a device; `detail.enforcement_point` says where it ran.
//   - A hold (ESCALATE) is outcome `ok`: the payer did what it should, which is
//     stop and wait. Only a DENY is `refused`. `detail.decision` keeps the word.
//   - A device_prompt row says the payer asked the owner to approve. It is only
//     emitted when the caller states the request was raised (`approvalRequested`).
//     What a device screen showed is never claimed.
//   - A device decision implied by a valid signature is `inferred`: we saw a
//     signature, not a press. With a software-key stand-in there is no device,
//     so there is no decision row at all.
//   - A stage this code did not observe is not emitted.
//   - verdictEvents cannot check that `challenge` is the real decoded header or
//     that `verdict` is the real Guard output. The labels describe what a
//     correct caller observed; they are not a proof.

import { keccak256, stringToHex, formatUnits } from "viem";
import { CHAIN_ID, RLUSD, RLUSD_DECIMALS } from "../config/network.js";
import { ALLOW, ESCALATE, DENY, amountFromAccepts } from "../guard/index.js";
import {
  SCHEMA,
  STAGES,
  EVENT_FIELDS,
  MAINNET_NETWORKS,
  AuditSchemaError,
  cleanSummary,
  checkEvent,
  validateEnvelope,
} from "./schema.js";

export {
  SCHEMA,
  OUTCOMES,
  ACTORS,
  UNITS,
  EVIDENCE,
  STAGES,
  MAINNET_NETWORKS,
  AuditSchemaError,
  cleanSummary,
  validateEnvelope,
} from "./schema.js";

/** XRPL EVM Testnet, CAIP-2. Built from the config's CHAIN_ID; 1440000 is mainnet. */
export const EVM_TESTNET_NETWORK = `eip155:${CHAIN_ID}`;

// Where the approver key lives. Same strings as ledger-approver/server/audit.mjs,
// so one run can mix rows from both producers. Left out means "not stated".
export const SOFTWARE_SIGNER = "software-key-standin";
export const EMULATOR_SIGNER = "ledger-emulator";
export const DEVICE_SIGNER = "ledger-device";
export const SIGNERS = Object.freeze([SOFTWARE_SIGNER, EMULATOR_SIGNER, DEVICE_SIGNER]);

const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;
const MAX_SUMMARY = 200;
const MAX_DETAIL_BYTES = 8192;

// The ESCALATE codes a single-use grant can answer (guard/index.js, CODES comment).
// UNKNOWN_MERCHANT and MANDATE_EXPIRED are checked before a grant is looked at,
// and reserve() refuses OVER_CHANNEL_CAP, so a grant clears none of those three.
const GRANT_CAN_ANSWER = new Set(["OVER_PER_CALL", "OVER_TOTAL", "OVER_WINDOW"]);

// ---------------------------------------------------------------- helpers

/** Unix seconds, a Date, an RFC 3339 string, or nothing (now). Output has seconds precision, like the schema's examples. */
function toTs(ts) {
  if (ts === undefined || ts === null) return new Date().toISOString().replace(/\.\d+Z$/, "Z");
  if (ts instanceof Date) return ts.toISOString().replace(/\.\d+Z$/, "Z");
  if (typeof ts === "number") {
    if (!Number.isFinite(ts)) throw new RangeError(`ts ${ts} is not a finite number of unix seconds`);
    return new Date(ts * 1000).toISOString().replace(/\.\d+Z$/, "Z");
  }
  // Anything else goes on as it is, so the validator reports it (an array is not a timestamp).
  return ts;
}

/** bigint -> string, undefined dropped. detail is JSON; a bigint would throw or round. */
function jsonSafe(v) {
  const text = JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
  return text === undefined ? undefined : JSON.parse(text);
}

/** detail is never rendered, but a hostile 402 should not be able to bloat the audit file. */
function boundedDetail(d) {
  const safe = jsonSafe(d);
  if (safe === undefined) return undefined;
  const bytes = JSON.stringify(safe).length;
  return bytes > MAX_DETAIL_BYTES ? { truncated: true, original_json_chars: bytes } : safe;
}

/** Summary text from outside (a merchant's URL, a Guard message): one line, bounded, no trailing stop. */
const oneLine = (s, max = MAX_SUMMARY) => cleanSummary(s, max);

function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(typeof v === "bigint" ? v.toString() : v);
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  return `{${Object.keys(v)
    .filter((k) => v[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
    .join(",")}}`;
}

/**
 * AP4M's 402 carries no invoice id, so tie events to one quote by hashing the
 * challenge itself. The same challenge always gives the same id.
 */
export function invoiceIdFor(challenge) {
  return keccak256(stringToHex(canon(challenge))).slice(2);
}

/**
 * An RLUSD base-unit figure as a USD decimal string, or null when it cannot be
 * done exactly. Only an all-digit string or a bigint qualifies (BigInt("0x10")
 * would also parse, and that is not a figure to put in an audit table), and only
 * when the asset is the RLUSD token this package is configured for.
 */
function exactUsd(units, asset) {
  if (typeof asset !== "string" || asset.toLowerCase() !== RLUSD.toLowerCase()) return null;
  const s = typeof units === "bigint" ? units.toString() : units;
  if (typeof s !== "string" || !/^\d+$/.test(s)) return null;
  return formatUnits(BigInt(s), RLUSD_DECIMALS);
}

const USD_BASIS =
  "RLUSD, 18-decimal base units divided by 10^18 exactly and labelled USD at face value; no market rate applied";

/** Money fields for an event, or {} when the figure cannot be stated exactly. */
function moneyFields(units, asset, ceilingUnits) {
  const amount = exactUsd(units, asset);
  if (amount === null) return { fields: {}, detail: units === undefined || units === null ? {} : { amount_raw: String(units).slice(0, 100) } };
  const fields = { amount, unit: "USD", asset: "RLUSD" };
  const ceiling = ceilingUnits === undefined ? null : exactUsd(ceilingUnits, asset);
  if (ceiling !== null) fields.ceiling = ceiling;
  return {
    fields,
    detail: { amount_basis: USD_BASIS, amount_base_units: String(units) },
  };
}

// ----------------------------------------------------------------- makeEvent

/**
 * Build one event. Fills `ts` when absent, checks the five required fields and
 * every other per-event rule, and throws AuditSchemaError if any fails.
 *
 * A string `summary` is made into one plain line first (control characters and
 * Unicode spaces removed, then any trailing full stop), the same way the
 * verdict builders treat outside text. A summary that is not a string, or that
 * is empty once cleaned, is refused.
 *
 * amount and ceiling may be a string or a bigint (exact); a JS number is
 * refused, because that is the rounding the schema forbids.
 *
 * @param {object} f  schema fields (ts, stage, outcome, actor, summary, amount, ...)
 */
export function makeEvent(f = {}) {
  const unknown = Object.keys(f).filter((k) => !EVENT_FIELDS.includes(k));
  if (unknown.length)
    throw new AuditSchemaError(`unknown event field(s): ${unknown.join(", ")}`, [
      { rule: "unknown-field", path: "event", message: unknown.join(", ") },
    ]);

  const e = {};
  for (const [k, v] of Object.entries(f)) if (v !== undefined) e[k] = v;
  e.ts = toTs(e.ts);
  if (typeof e.summary === "string") e.summary = cleanSummary(e.summary);

  for (const k of ["amount", "ceiling"]) {
    if (typeof e[k] === "bigint") e[k] = e[k].toString();
    else if (typeof e[k] === "number")
      throw new AuditSchemaError(`${k} is a number; pass a string or bigint`, [
        { rule: 5, path: "event", message: `${k} must be a string, got number` },
      ]);
  }
  if (e.detail !== undefined) {
    e.detail = boundedDetail(e.detail);
    if (e.detail === undefined) delete e.detail;
  }

  const { errors } = checkEvent(e, "event");
  if (e.stage !== undefined && !STAGES.includes(e.stage))
    errors.push({ rule: "stage-unknown", path: "event", message: `stage ${JSON.stringify(e.stage)} is not in the agent-audit/1 schema` });
  if (e.ceiling !== undefined && e.unit === undefined)
    errors.push({ rule: "ceiling-unit", path: "event", message: "ceiling given without unit" });

  if (errors.length)
    throw new AuditSchemaError(`invalid event: ${errors.map((x) => `[${x.rule}] ${x.message}`).join("; ")}`, errors);
  return e;
}

// ------------------------------------------------------------- verdictEvents

const CEILING_KEYS = {
  OVER_PER_CALL: "maxPerCall",
  OVER_TOTAL: "maxTotal",
  OVER_WINDOW: "maxPerWindow",
  OVER_CHANNEL_CAP: "channelCap",
};

const VERDICT_OPTIONS = [
  "challenge",
  "verdict",
  "mandateId",
  "intent",
  "ts",
  "mandate",
  "approvalRequested",
  "signer",
  "grantAnswer",
  "settlement",
];

// What a valid grant signature lets us say, by where the approver key lives.
// The signer option is the caller's statement; nothing here can check it.
const APPROVAL_WORDING = {
  [DEVICE_SIGNER]: [
    "a valid signature from the registered approver key arrived, which implies the owner approved on the device",
    "the payer saw only a valid signature from the registered approver key; the key lives on the device, so a press is inferred, not observed",
  ],
  [EMULATOR_SIGNER]: [
    "a valid signature from the registered approver key arrived, which implies the owner approved in the Speculos emulator; the key is in the emulator and no physical device was involved",
    "the payer saw only a valid signature from the registered approver key; the key is held by the Speculos emulator, so an approval there is inferred, not observed; no physical device was involved",
  ],
  unstated: [
    "a valid signature from the registered approver key arrived, which implies the owner approved; where the key lives is not stated",
    "the payer saw only a valid signature from the registered approver key; where that key lives is not stated, so an approval is inferred, not observed",
  ],
};

const SOFTWARE_BASIS = "the signing key is a software key held by a script; no hardware device signed and no button was pressed";

/**
 * Turn one 402 and the Guard's answer to it into audit events.
 *
 *   quote           merchant    always, when a challenge is given
 *   policy_check    facilitator always; ok+measured for ALLOW and for a hold (ESCALATE), refused+measured for DENY
 *   device_prompt   facilitator only when approvalRequested is true; the payer asked, nothing about a screen
 *   device_decision owner       only for a grantAnswer that shows a decision, and never for a software stand-in
 *   settle          merchant/ledger  only when settlement.txHash is a real 0x hash
 *
 * Why policy_check is actor "facilitator": the schema has no policy actor. The
 * Guard is a library inside the payer, so it is neither the merchant, the model
 * nor a device. `detail.decided_by` and `detail.enforcement_point` say what it is.
 * A payer whose host is fully compromised can skip the library; README says so.
 *
 * @param {object} p
 * @param {object}  [p.challenge]  decoded PAYMENT-REQUIRED. Omit it when the payer stopped before asking (revocation).
 * @param {object}   p.verdict     { decision, code, detail, message } from evaluate()
 * @param {string}  [p.mandateId]
 * @param {string}  [p.intent]     the agent's user_intent, verbatim
 * @param {number|Date|string} [p.ts]
 * @param {object}  [p.mandate]    typed data from buildMandate(), only to state the per-call ceiling on an ALLOW
 * @param {boolean} [p.approvalRequested] true only if the caller raised an approval request for this ESCALATE; no default
 * @param {string}  [p.signer]     where the approver key lives: SOFTWARE_SIGNER, EMULATOR_SIGNER or DEVICE_SIGNER; left out = not stated
 * @param {{status:"signed"|"rejected"|"error", signatureValid?:boolean, grantId?:string, approver?:string, ts?:*, error?:string}} [p.grantAnswer]
 * @param {{txHash:string, explorerUrl?:string, txResult?:string, chainReceipt?:{status:(number|bigint), blockNumber?:(number|bigint|string)}}} [p.settlement]
 * @returns {object[]} events, oldest first
 */
export function verdictEvents(params = {}) {
  const stray = Object.keys(params).filter((k) => !VERDICT_OPTIONS.includes(k));
  if (stray.length) throw new TypeError(`verdictEvents: unknown option(s): ${stray.join(", ")}`);
  const { challenge, verdict, mandateId, intent, ts, mandate, approvalRequested, signer, grantAnswer, settlement } = params;

  if (!verdict || ![ALLOW, ESCALATE, DENY].includes(verdict.decision))
    throw new TypeError("verdictEvents: verdict.decision must be ALLOW, ESCALATE or DENY");
  if (settlement && verdict.decision !== ALLOW)
    throw new TypeError("verdictEvents: settlement given for a verdict that did not allow payment");
  if (signer !== undefined && !SIGNERS.includes(signer))
    throw new TypeError(`verdictEvents: signer must be one of ${SIGNERS.join(", ")} or left out (left out = not stated)`);
  if (approvalRequested !== undefined && typeof approvalRequested !== "boolean")
    throw new TypeError("verdictEvents: approvalRequested must be true or false");
  if (approvalRequested === true && verdict.decision !== ESCALATE)
    throw new TypeError("verdictEvents: approvalRequested given for a verdict that is not ESCALATE");
  if (grantAnswer && !["signed", "rejected", "error"].includes(grantAnswer.status))
    throw new TypeError("verdictEvents: grantAnswer.status must be signed, rejected or error");

  const when = toTs(ts);
  const events = [];
  const accepts = Array.isArray(challenge?.accepts) ? challenge.accepts : [];
  // Several options means the amount is ambiguous, so no amount is stated.
  const accepted = accepts.length === 1 ? accepts[0] : null;
  const units = accepted ? amountFromAccepts(accepted) : null;
  // The Guard reads "0x10" as 16. An audit table should not: convert only the figure as the merchant wrote it,
  // and only if that is plain digits. Same field order as amountFromAccepts.
  const rawAmount = accepted?.amount ?? accepted?.maxAmountRequired ?? accepted?.value ?? accepted?.price;
  const invoice_id = challenge ? invoiceIdFor(challenge) : undefined;
  const resource = challenge?.resource?.url;

  const money = accepted && units !== null ? moneyFields(rawAmount, accepted.asset) : { fields: {}, detail: {} };

  // ---- quote: what the merchant asked for ----
  if (challenge) {
    events.push(
      makeEvent({
        ts: when,
        stage: "quote",
        actor: "merchant",
        outcome: "ok",
        evidence: "measured",
        summary: oneLine(
          money.fields.amount
            ? `402 quote of ${money.fields.amount} RLUSD for ${resource ?? "an unnamed resource"}`
            : `402 challenge received for ${resource ?? "an unnamed resource"}`,
        ),
        ...money.fields,
        ceiling: undefined,
        invoice_id,
        detail: {
          ...money.detail,
          resource,
          accepts_count: accepts.length,
          ...(accepted && {
            scheme: accepted.scheme,
            network: accepted.network,
            asset_address: accepted.asset,
            pay_to: accepted.payTo,
            channel_id: accepted.extra?.channelId,
          }),
          invoice_id_basis: "keccak-256 of the canonical JSON of the decoded challenge; AP4M's 402 carries no invoice id",
        },
      }),
    );
  }

  // ---- policy_check: the Guard's verdict ----
  let ceilingUnits;
  const ck = CEILING_KEYS[verdict.code];
  if (ck && verdict.detail?.[ck] !== undefined) ceilingUnits = verdict.detail[ck];
  else if (verdict.decision === ALLOW && verdict.code === "WITHIN_MANDATE" && mandate?.message?.maxPerCall !== undefined)
    ceilingUnits = mandate.message.maxPerCall;
  const withCeiling = accepted && units !== null ? moneyFields(rawAmount, accepted.asset, ceilingUnits) : money;

  const checkSummary = {
    [ALLOW]:
      verdict.code === "WITHIN_GRANT"
        ? "Guard allowed the payment on a grant whose signature verified"
        : "Guard allowed the payment inside the signed mandate",
    [ESCALATE]: `Guard held the payment for owner approval (${verdict.code}): ${verdict.message}`,
    [DENY]: `Guard denied the payment (${verdict.code}): ${verdict.message}`,
  }[verdict.decision];

  // A hold is the Guard working: the payer stopped and is waiting. Only a DENY is a refusal.
  const usedGrant = verdict.code === "WITHIN_GRANT";
  events.push(
    makeEvent({
      ts: when,
      stage: "policy_check",
      actor: "facilitator",
      outcome: verdict.decision === DENY ? "refused" : "ok",
      evidence: "measured",
      summary: oneLine(checkSummary),
      ...withCeiling.fields,
      invoice_id,
      policy: verdict.code,
      intent: intent === undefined ? undefined : String(intent),
      detail: {
        decision: verdict.decision,
        code: verdict.code,
        guard_message: verdict.message,
        decided_by: "spend-gate Guard: deterministic code reading the owner-signed mandate, not the model",
        enforcement_point: "in-process library inside the payer, reading an owner-signed mandate",
        not_checked_here:
          "mandate signature, revocation state and grant signature are resolved by the caller before evaluate(); this event cannot re-check them",
        mandate_id: mandateId,
        ...(withCeiling.fields.ceiling !== undefined && { ceiling_kind: ck ?? "maxPerCall" }),
        ...withCeiling.detail,
        // The row that relied on a grant carries where its signature came from.
        ...(usedGrant && signer !== undefined && { signer }),
        ...(usedGrant && signer === SOFTWARE_SIGNER && { basis: SOFTWARE_BASIS }),
        verdict_detail: verdict.detail,
      },
    }),
  );

  // ---- device_prompt: only when the caller says it asked the owner ----
  if (approvalRequested === true) {
    const grantClears = GRANT_CAN_ANSWER.has(verdict.code);
    events.push(
      makeEvent({
        ts: when,
        stage: "device_prompt",
        actor: "facilitator",
        outcome: "ok",
        evidence: "measured",
        summary: grantClears
          ? "payer asked the owner to approve this one payment; what a device screen showed is not observed"
          : `payer asked the owner to act on ${verdict.code}; a one-payment grant does not clear this; what a device screen showed is not observed`,
        ...money.fields,
        invoice_id,
        detail: {
          ask: { pay_to: accepted?.payTo, resource, amount_base_units: units === null ? undefined : units },
          grant_can_clear: grantClears,
          ...(!grantClears &&
            (verdict.code === "UNKNOWN_MERCHANT" || verdict.code === "MANDATE_EXPIRED") && {
              resolved_by: "a new signed mandate",
            }),
          source: "the caller stated the approval request was raised",
          observed: "the payer side only; what the device screen showed is not observed",
        },
      }),
    );
  }

  // ---- device_decision: the owner's answer, if a Grant came back ----
  if (grantAnswer) {
    const a = grantAnswer;
    const base = { ts: a.ts === undefined ? when : toTs(a.ts), stage: "device_decision" };
    const grantInfo = { grant_id: a.grantId, approver: a.approver, ...(signer !== undefined && { signer }) };
    if (a.status === "signed" && a.signatureValid === true) {
      // With a software-key stand-in nobody approved on a device, so there is no decision to infer.
      if (signer !== SOFTWARE_SIGNER) {
        const [summary, basis] = APPROVAL_WORDING[signer] ?? APPROVAL_WORDING.unstated;
        events.push(
          makeEvent({
            ...base,
            actor: "owner",
            outcome: "ok",
            evidence: "inferred",
            summary,
            detail: {
              ...grantInfo,
              basis,
              not_observed: "the device screen and the button press were not watched by this call",
            },
          }),
        );
      }
    } else if (a.status === "rejected") {
      // The signer reported a rejection (measured), but nothing here authenticates who
      // pressed it, so that the owner refused is inferred.
      events.push(
        makeEvent({
          ...base,
          actor: "owner",
          outcome: "refused",
          evidence: "inferred",
          summary:
            signer === SOFTWARE_SIGNER
              ? "the signer reported a rejection of the grant (a software key stands in for the device); nothing was signed"
              : "the signer reported a rejection of the grant; nothing was signed",
          detail: {
            ...grantInfo,
            basis:
              "the signer reported a user rejection (measured); nothing here authenticates who pressed it, so that the owner refused is inferred",
            ...(signer === SOFTWARE_SIGNER && { stand_in: SOFTWARE_BASIS }),
          },
        }),
      );
    } else if (a.status === "error") {
      events.push(
        makeEvent({
          ...base,
          actor: "facilitator",
          outcome: "error",
          evidence: "measured",
          summary: "the signer returned an error instead of a grant signature; no grant was obtained",
          detail: { ...grantInfo, error: a.error === undefined ? undefined : oneLine(a.error, 300) },
        }),
      );
    }
    // status "signed" with an invalid signature is not an owner decision at all.
    // Nothing shows a person decided anything, so no event; the Guard's DENY
    // (BAD_GRANT_SIGNATURE) in policy_check is the record.
  }

  // ---- settle: only with a real transaction hash ----
  if (settlement && settlement.txHash !== undefined && settlement.txHash !== null) {
    if (!TX_HASH.test(String(settlement.txHash)))
      throw new TypeError("verdictEvents: settlement.txHash must be 0x followed by 64 hex characters");
    const r = settlement.chainReceipt;
    const onChain = r !== undefined && r !== null;
    const reverted = onChain && Number(r.status) !== 1;
    events.push(
      makeEvent({
        ts: when,
        stage: "settle",
        actor: onChain ? "ledger" : "merchant",
        outcome: reverted ? "error" : "ok",
        evidence: onChain ? "measured" : "inferred",
        summary: reverted
          ? "settlement transaction reverted on chain"
          : onChain
            ? "payment settled; transaction receipt read from chain"
            : "merchant reported settlement; not checked on chain",
        ...money.fields,
        invoice_id,
        // EVM form: 0x and lowercase hex, as ethers prints it. An XRPL hash would be 64 uppercase hex.
        tx_hash: String(settlement.txHash).toLowerCase(),
        tx_result: settlement.txResult,
        explorer_url: settlement.explorerUrl,
        detail: {
          // Who was paid, as the merchant's 402 named it (accepts[0].payTo). Left out when payTo is missing or empty.
          ...(typeof accepted?.payTo === "string" && accepted.payTo !== "" && { destination: accepted.payTo }),
          verified_on_chain: onChain && !reverted,
          source: onChain ? "transaction receipt" : "merchant PAYMENT-RESPONSE header",
          ...(onChain && { receipt_status: String(r.status), block_number: r.blockNumber === undefined ? undefined : String(r.blockNumber) }),
        },
      }),
    );
  }

  // Newest last. Stable, so events sharing a timestamp keep the order built above.
  return events
    .map((e, i) => ({ e, i, t: Date.parse(e.ts) }))
    .sort((x, y) => x.t - y.t || x.i - y.i)
    .map((x) => x.e);
}

// ------------------------------------------------------------------ envelope

/** `<RFC 3339 time>/<label>`, like the schema's example run_id. */
export function makeRunId(label, ts) {
  if (!label || /[\s]/.test(label)) throw new TypeError("makeRunId: label must be a non-empty string without spaces");
  return `${toTs(ts)}/${label}`;
}

/**
 * The file a reader loads. Validated before it is returned: an invalid envelope
 * throws, so a producer cannot write one by accident.
 *
 * @param {object} p
 * @param {string}  p.run_id
 * @param {string} [p.network]  CAIP-2; defaults to XRPL EVM Testnet (eip155:1449000)
 * @param {object[]} p.events
 * @param {string[]} [p.forbidNetworks]  networks refused by chain id; defaults to MAINNET_NETWORKS (eip155:1440000), [] allows anything
 */
export function envelope({ run_id, network = EVM_TESTNET_NETWORK, events, forbidNetworks = MAINNET_NETWORKS } = {}) {
  if (typeof network !== "string" || !CAIP2.test(network))
    throw new AuditSchemaError(`network ${JSON.stringify(network)} is not a CAIP-2 identifier`, [
      { rule: "network-format", path: "envelope", message: String(network) },
    ]);
  const doc = { schema: SCHEMA, run_id, network, events: Array.isArray(events) ? [...events] : events };
  const { ok, errors } = validateEnvelope(doc, { forbidNetworks });
  if (!ok)
    throw new AuditSchemaError(
      `invalid envelope: ${errors.map((x) => `${x.path}: [${x.rule}] ${x.message}`).join("; ")}`,
      errors,
    );
  return doc;
}
