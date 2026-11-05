// AP2 v0.2 Payment Mandates as a spend-gate mandate source.
//
// The user signs an OPEN Payment Mandate (vct `mandate.payment.open.1`) that
// delegates to the agent's key (`cnf.jwk`). This module verifies it and turns
// its constraints into the envelope the Guard already enforces:
//
//   payment.amount_range.max   -> maxPerCall
//   payment.budget.max         -> maxTotal
//   payment.allowed_payees     -> merchant (exactly one, an EVM address)
//   payment.execution_date     -> validFrom / validUntil (with iat / exp)
//   payment.agent_recurrence   -> ON_DEMAND only
//   payment.allowed_payment_instruments -> must list this x402 instrument
//
// A constraint this module cannot enforce exactly is refused, not ignored. The
// one exception the caller may opt into is `payment.reference`: it ties the
// mandate to an AP2 Checkout Mandate, and an x402 resource purchase has none,
// so it cannot be checked here. The caller must name it in `allowUnchecked`.
//
// After each payment the agent can sign a CLOSED Payment Mandate
// (vct `mandate.payment.1`) chained to the open one: AP2's own receipt that this
// payment was made under the user's mandate. AP2 defines `transaction_id` as a
// hash of a checkout JWT. For x402 we use the hash of the merchant's
// PAYMENT-REQUIRED header: this binding is ours, not part of the AP2 spec.

import { getAddress, isAddress } from "viem";
import { verifyChain, appendHop, hashAscii } from "./sdjwt.js";
import { buildMandate } from "../mandate/index.js";
import { RLUSD, RLUSD_DECIMALS, CHAIN_ID } from "../config/network.js";

export const VCT_OPEN_PAYMENT = "mandate.payment.open.1";
export const VCT_PAYMENT = "mandate.payment.1";
export const X402_INSTRUMENT_TYPE = "x402.exact";

/** ISO 4217 minor-unit exponents this module knows. Others are refused. */
const MINOR_EXPONENT = { USD: 2, EUR: 2, GBP: 2 };

const KNOWN = new Set([
  "payment.amount_range",
  "payment.budget",
  "payment.allowed_payees",
  "payment.execution_date",
  "payment.agent_recurrence",
  "payment.allowed_payment_instruments",
  "payment.allowed_pisps",
  "payment.reference",
]);

export class Ap2Error extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.code = code;
    this.detail = detail;
  }
}

/** CAIP-19 id of an ERC-20 asset. */
export const caip19 = (chainId, asset) => `eip155:${chainId}/erc20:${getAddress(asset)}`;

/** The payment instrument an x402 `exact` payment on this asset uses, in AP2 form. */
export function x402Instrument({ chainId = CHAIN_ID, asset = RLUSD } = {}) {
  return { id: caip19(chainId, asset), type: X402_INSTRUMENT_TYPE, description: "x402 exact (EIP-3009)" };
}

/** A payee id in AP2 as an EVM address: a bare address or CAIP-10 `eip155:<chainId>:<address>`. */
function payeeAddress(id, chainId) {
  if (typeof id !== "string") return null;
  if (isAddress(id)) return getAddress(id);
  const m = /^eip155:(\d+):(0x[0-9a-fA-F]{40})$/.exec(id);
  if (m && Number(m[1]) === Number(chainId)) return getAddress(m[2]);
  return null;
}

const toUnix = (iso, what) => {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new Ap2Error("AP2_MALFORMED", `${what} is not an ISO 8601 date: ${iso}`);
  return Math.floor(t / 1000);
};

/**
 * Convert between AP2 minor units and on-chain base units of a token pegged 1:1
 * to `currency`. 1 cent of USD = 10^(decimals-2) base units.
 */
export function unitScale(currency, assetDecimals) {
  const exp = MINOR_EXPONENT[currency];
  if (exp === undefined) throw new Ap2Error("AP2_CURRENCY_UNSUPPORTED", `currency ${currency} is not supported`);
  if (assetDecimals < exp) throw new Ap2Error("AP2_CURRENCY_UNSUPPORTED", "asset has fewer decimals than the currency");
  return 10n ** BigInt(assetDecimals - exp);
}

function minorInteger(v, what) {
  if (!Number.isSafeInteger(v) || v < 0)
    throw new Ap2Error("AP2_MALFORMED", `${what} must be a non-negative integer in minor units, got ${v}`);
  return BigInt(v);
}

/**
 * Verify an open Payment Mandate chain against the user's public key.
 * @returns {Promise<{open: object, agentJwk: object}>}
 */
export async function verifyOpenPaymentMandate(token, userJwk, { now } = {}) {
  let hops;
  try {
    ({ hops } = await verifyChain(token, userJwk, { now }));
  } catch (e) {
    throw new Ap2Error("AP2_SIGNATURE_INVALID", `open payment mandate does not verify: ${e.message}`);
  }
  const last = hops[hops.length - 1];
  const open = last.items[0];
  if (hops.some((h) => h.items.length !== 1)) throw new Ap2Error("AP2_MALFORMED", "each hop must carry exactly one mandate");
  if (open?.vct !== VCT_OPEN_PAYMENT) throw new Ap2Error("AP2_WRONG_TYPE", `expected ${VCT_OPEN_PAYMENT}, got ${open?.vct}`);
  if (!open.cnf?.jwk) throw new Ap2Error("AP2_MALFORMED", "open payment mandate has no cnf.jwk for the agent");
  if (!Array.isArray(open.constraints)) throw new Ap2Error("AP2_MALFORMED", "open payment mandate has no constraints");
  return { open, agentJwk: open.cnf.jwk };
}

/**
 * Turn a verified open Payment Mandate into a spend-gate mandate.
 *
 * @param {object} open                 the verified open mandate (from verifyOpenPaymentMandate)
 * @param {object} cfg
 * @param {string} cfg.agent            the agent's EVM address (it signs the EIP-3009 authorizations)
 * @param {string} cfg.registry         MandateRegistry address (EIP-712 domain of the result)
 * @param {string} [cfg.asset]          token the agent pays in (default RLUSD)
 * @param {number} [cfg.assetDecimals]
 * @param {number} [cfg.chainId]
 * @param {string[]} [cfg.allowUnchecked]  constraint types the caller accepts unchecked
 * @returns {{mandate: object, currency: string, unchecked: string[], scale: bigint, maxPayments: number|null}}
 *   `maxPayments` is 1 when the mandate has no agent_recurrence. The caller must
 *   enforce it: the Guard caps amounts, not counts.
 */
export function toGuardMandate(
  open,
  { agent, registry, asset = RLUSD, assetDecimals = RLUSD_DECIMALS, chainId = CHAIN_ID, allowUnchecked = [] },
) {
  const byType = new Map();
  for (const c of open.constraints) {
    if (!c || typeof c.type !== "string") throw new Ap2Error("AP2_MALFORMED", "a constraint has no type");
    if (!KNOWN.has(c.type)) throw new Ap2Error("AP2_CONSTRAINT_UNSUPPORTED", `unknown constraint ${c.type}`, { type: c.type });
    if (byType.has(c.type)) throw new Ap2Error("AP2_CONSTRAINT_UNSUPPORTED", `constraint ${c.type} appears twice`, { type: c.type });
    byType.set(c.type, c);
  }
  const unsupported = (type, why) => {
    throw new Ap2Error("AP2_CONSTRAINT_UNSUPPORTED", `${type}: ${why}`, { type });
  };

  const range = byType.get("payment.amount_range");
  if (!range) unsupported("payment.amount_range", "required: without it there is no per-payment cap");
  const currency = range.currency;
  const scale = unitScale(currency, assetDecimals);
  if (range.min !== undefined && range.min !== 0) unsupported("payment.amount_range", "a minimum above 0 is not enforced");
  const maxPerCall = minorInteger(range.max, "amount_range.max") * scale;

  const budget = byType.get("payment.budget");
  let maxTotal = maxPerCall;
  if (budget) {
    if (budget.currency !== currency) unsupported("payment.budget", "currency differs from amount_range");
    maxTotal = minorInteger(budget.max, "budget.max") * scale;
  }

  // Without agent_recurrence the mandate is not reusable: it pays once.
  const recurrence = byType.get("payment.agent_recurrence");
  let maxPayments = 1;
  if (recurrence) {
    if (recurrence.frequency !== "ON_DEMAND") unsupported("payment.agent_recurrence", `frequency ${recurrence.frequency} is not enforced`);
    if (recurrence.max_occurrences !== undefined) unsupported("payment.agent_recurrence", "max_occurrences is not enforced");
    maxPayments = null;
  } else {
    maxTotal = maxPerCall;
  }

  const payees = byType.get("payment.allowed_payees");
  if (!payees) unsupported("payment.allowed_payees", "required: without it any payee would be allowed");
  if (!Array.isArray(payees.allowed) || payees.allowed.length !== 1)
    unsupported("payment.allowed_payees", "exactly one payee is supported");
  const merchant = payeeAddress(payees.allowed[0]?.id, chainId);
  if (!merchant) unsupported("payment.allowed_payees", `payee id ${payees.allowed[0]?.id} is not an address on eip155:${chainId}`);

  const instruments = byType.get("payment.allowed_payment_instruments");
  if (instruments) {
    const mine = x402Instrument({ chainId, asset });
    const ok = (instruments.allowed ?? []).some((i) => i?.type === mine.type && String(i?.id).toLowerCase() === mine.id.toLowerCase());
    if (!ok) throw new Ap2Error("AP2_INSTRUMENT_NOT_ALLOWED", `the mandate does not allow ${mine.id} via ${mine.type}`);
  }

  if (byType.has("payment.allowed_pisps")) unsupported("payment.allowed_pisps", "x402 has no PISP");

  const unchecked = [];
  if (byType.has("payment.reference")) {
    if (!allowUnchecked.includes("payment.reference"))
      throw new Ap2Error(
        "AP2_REFERENCE_UNVERIFIABLE",
        "payment.reference ties the mandate to an AP2 checkout, which an x402 purchase does not have; pass allowUnchecked: ['payment.reference'] to accept it unchecked",
      );
    unchecked.push("payment.reference");
  }

  let from = typeof open.iat === "number" ? open.iat : null;
  let until = typeof open.exp === "number" ? open.exp : null;
  const window = byType.get("payment.execution_date");
  if (window?.not_before) from = Math.max(from ?? 0, toUnix(window.not_before, "execution_date.not_before"));
  if (window?.not_after) {
    const na = toUnix(window.not_after, "execution_date.not_after");
    until = until === null ? na : Math.min(until, na);
  }
  if (until === null) throw new Ap2Error("AP2_MALFORMED", "the mandate has no end: set exp or execution_date.not_after");
  from = from ?? Math.floor(Date.now() / 1000);

  // The whole budget may be spent in one window: AP2 has no per-window cap.
  const windowSeconds = BigInt(Math.max(1, until - from));
  const mandate = buildMandate({
    agent,
    asset,
    merchant,
    maxPerCall,
    maxPerWindow: maxTotal,
    windowSeconds,
    maxTotal,
    validFrom: from,
    validUntil: until,
    purpose: `ap2:${hashAscii(JSON.stringify(open), "sha-256").slice(0, 16)}`,
    nonce: from,
    chainId,
    registry,
  });
  return { mandate, currency, unchecked, scale, maxPayments };
}

/** AP2 `transaction_id` for an x402 payment: base64url(sha-256(PAYMENT-REQUIRED header)). */
export const transactionIdForChallenge = (paymentRequiredHeader) => hashAscii(String(paymentRequiredHeader), "sha-256");

/**
 * Sign a closed Payment Mandate for one settled payment, chained to the open one.
 *
 * @param {object} p
 * @param {string} p.openToken         the open mandate chain the agent holds
 * @param {object} p.agentPrivateJwk   private half of the open mandate's cnf.jwk
 * @param {object} p.payee             AP2 Merchant {id, name}
 * @param {bigint} p.amount            base units paid
 * @param {bigint} p.scale             base units per minor unit (from toGuardMandate)
 * @param {string} p.currency
 * @param {object} p.instrument        AP2 PaymentInstrument
 * @param {string} p.transactionId
 * @param {string} p.aud               who will verify it (e.g. the merchant's origin)
 * @param {string} p.nonce
 */
export async function signClosedPaymentMandate({ openToken, agentPrivateJwk, payee, amount, scale, currency, instrument, transactionId, aud, nonce, iat }) {
  if (amount % scale !== 0n)
    throw new Ap2Error("AP2_AMOUNT_NOT_REPRESENTABLE", `${amount} base units is not a whole number of ${currency} minor units`);
  const minor = amount / scale;
  if (minor > BigInt(Number.MAX_SAFE_INTEGER)) throw new Ap2Error("AP2_AMOUNT_NOT_REPRESENTABLE", "amount is too large");
  const closed = {
    vct: VCT_PAYMENT,
    transaction_id: transactionId,
    payee,
    payment_amount: { amount: Number(minor), currency },
    payment_instrument: instrument,
  };
  return { closed, token: await appendHop(openToken, closed, agentPrivateJwk, { aud, nonce, iat }) };
}
