// The payer: the only component that touches the network, and the only place
// where a Guard verdict turns into money moving.
//
// It is deliberately thin. x402 already defines the handshake and the open
// `@x402/core` + `@x402/evm` packages already encode the wire format and sign the
// `exact` scheme's EIP-3009 authorization; neither decides whether a payment
// SHOULD happen. That decision is `evaluate()` in src/guard, and the ordering
// here is the whole point:
//
//   GET -> 402 -> decode -> evaluate() -> reserve() -> sign -> check -> retry -> commit
//
// Four ordering rules, each of which is a bug if broken:
//   1. evaluate() runs before anything is reserved or signed. A DENY must cost
//      nothing and leave no trace in the spend ledger.
//   2. reserve() runs before the authorization is signed. A signed authorization
//      is a bearer instrument — once it leaves the process the money can move —
//      so the budget is debited first. reserve() is the enforcement point;
//      evaluate() only explains (src/README.md, design decision 2).
//   3. The signed payload is checked against the accept the Guard evaluated
//      BEFORE it leaves the process. The x402 client picks requirements itself;
//      if what it signed differs from what was approved, nothing is sent.
//   4. release() runs on every failure path. An abandoned reservation that is
//      never released permanently shrinks the budget.
//
// `signer` is injected so one code path serves both the test (local key) and
// the demo (Ledger device). The payer never sees a private key.

import { x402Client } from "@x402/core/client";
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import {
  evaluate,
  ALLOW,
  ESCALATE,
  DENY,
  amountFromAccepts,
  describeVerdict,
} from "../guard/index.js";
import { hashMandate } from "../mandate/index.js";
import { hashGrant } from "../mandate/grant.js";
import { HEADERS, X402_NETWORK } from "../config/network.js";

/** Outcomes of buy(). `requires_confirmation` reuses the seam x402 SDKs already expose. */
export const PAID = "paid";
export const REQUIRES_CONFIRMATION = "requires_confirmation";
export const REFUSED = "refused";
export const FAILED = "failed";
/** Outcome of a dry run: the verdict a payment would get. Nothing reserved, signed or recorded. */
export const CHECKED = "checked";

/**
 * Wrap a signer into the shape @x402/evm wants: `{ address, signTypedData({domain,
 * types, primaryType, message}) }`. A viem account already has it. An ethers signer
 * (and the Ledger device approver, which mimics one) signs as
 * `signTypedData(domain, types, value)` and rejects an `EIP712Domain` entry.
 */
export async function toX402Signer(signer) {
  if (typeof signer?.getAddress !== "function") return signer;
  const address = await signer.getAddress();
  return {
    address,
    async signTypedData({ domain, types, message }) {
      const { EIP712Domain: _drop, ...rest } = types;
      return signer.signTypedData(domain, rest, message);
    },
  };
}

/** The fields of an accept that decide where money goes and how much. */
const BINDING_FIELDS = ["scheme", "network", "asset", "payTo"];

function sameAccept(signed, evaluated) {
  for (const f of BINDING_FIELDS)
    if (String(signed?.[f] ?? "").toLowerCase() !== String(evaluated?.[f] ?? "").toLowerCase())
      return { ok: false, field: f, got: signed?.[f], want: evaluated?.[f] };
  if (amountFromAccepts(signed) !== amountFromAccepts(evaluated))
    return { ok: false, field: "amount", got: signed?.amount, want: evaluated?.amount };
  return { ok: true };
}

/**
 * @param {object} cfg
 * @param {object}   cfg.mandate          EIP-712 typed data from buildMandate()
 * @param {boolean}  cfg.signatureValid   pre-resolved verifyMandate() result
 * @param {object}   cfg.ledger           SpendLedger instance
 * @param {object}   cfg.signer           viem account, or ethers-style signer (see toX402Signer)
 * @param {string}   [cfg.network]        CAIP-2 network to pay on (default X402_NETWORK)
 * @param {object}   [cfg.policy]         extra Guard policy (expectedPrice, …)
 * @param {object}   [cfg.client]         injectable x402Client (tests)
 * @param {function} [cfg.fetchImpl]      injectable fetch
 * @param {function} [cfg.now]            () => unix seconds
 * @param {function} [cfg.onEvent]        audit sink; every verdict and payment passes through it
 * @param {function} [cfg.isRevoked]      (mandateId) => boolean, for callers with their own state
 * @param {object}   [cfg.revocation]     a checker from src/revocation; fails closed (preferred)
 */
export function createPayer({
  mandate,
  signatureValid,
  ledger,
  signer,
  network = X402_NETWORK,
  policy = {},
  client = null,
  fetchImpl = globalThis.fetch,
  now = () => Math.floor(Date.now() / 1000),
  onEvent = () => {},
  isRevoked = () => false,
  revocation = null,
}) {
  const mandateId = hashMandate(mandate);
  const windowSeconds = Number(mandate.message.windowSeconds);
  const audit = [];

  // The x402 client's own spend controls are off on purpose: the mandate is the
  // spend authority, and two caps that can disagree make refusals unexplainable.
  let x402 = client;
  const getClient = async () => {
    if (!x402)
      x402 = x402Client.fromConfig({
        schemes: [{ network, client: new ExactEvmScheme(await toX402Signer(signer)) }],
        spendControls: false,
      });
    return x402;
  };

  const emit = (event) => {
    audit.push(event);
    onEvent(event);
    return event;
  };

  /**
   * Attempt to buy `url`, paying automatically if and only if the Guard allows.
   * Never throws on a refusal — a refusal is a result, not an exception.
   *
   * @param {string} url
   * @param {object} [o]
   * @param {object} [o.init]   fetch init
   * @param {object} [o.grant]  a device-signed Grant resolving an earlier ESCALATE
   *                            for this exact payment (src/mandate/grant.js)
   * @param {boolean} [o.grantSignatureValid] resolved by the caller
   * @param {boolean} [o.dryRun]  stop after the verdict: reserve, sign and record nothing
   */
  async function buy(url, { init = {}, grant = null, grantSignatureValid = false, dryRun = false } = {}) {
    const gid = grant ? hashGrant(grant) : null;
    // A dry run returns what it found and records nothing.
    const done = dryRun ? (e) => e : emit;

    // Revocation is checked FIRST, before the resource is even requested.
    // Asking a merchant to quote a payment we are not allowed to make leaks
    // intent and wastes a round trip, and the checker fails closed — "could not
    // read the registry" stops the agent just as "revoked" does, with the
    // reason carried through so a human can tell the two apart.
    if (revocation) {
      const r = await revocation.check(mandateId);
      if (r.revoked)
        return done({
          outcome: REFUSED,
          url,
          verdict: {
            decision: DENY,
            code: r.source === "live" || r.source === "cached" ? "REVOKED" : "REVOCATION_UNKNOWN",
            detail: { source: r.source, ...(r.detail ?? {}) },
            message: r.detail?.message ?? "mandate has been revoked",
          },
          revocation: r,
          message: `stopped: ${r.detail?.message ?? `mandate revoked (${r.source})`}`,
        });
    }

    const headers = { ...(init.headers ?? {}) };
    const first = await fetchImpl(url, { ...init, headers });
    if (first.status !== 402)
      return done({ outcome: dryRun ? CHECKED : PAID, url, free: true, status: first.status, response: first });

    const header = first.headers.get(HEADERS.required);
    if (!header)
      return done({
        outcome: FAILED,
        url,
        code: "NO_CHALLENGE_HEADER",
        message: `402 without a ${HEADERS.required} header`,
      });

    let challenge;
    try {
      challenge = decodePaymentRequiredHeader(header);
    } catch (e) {
      return done({ outcome: FAILED, url, code: "UNDECODABLE_CHALLENGE", message: e.message });
    }

    // --- 1. decide, before touching the budget or the signer ---
    const verdict = evaluate({
      mandate,
      mandateId,
      signatureValid,
      revoked: isRevoked(mandateId),
      challenge,
      agent: mandate.message.agent,
      now: now(),
      spend: ledger.snapshot(mandateId, { windowSeconds }),
      grant,
      grantId: gid,
      grantSignatureValid,
      grantConsumed: gid ? ledger.isGrantUsed(gid) : false,
      policy: { expectedNetwork: network, ...policy },
    });

    if (dryRun)
      return {
        outcome: CHECKED,
        url,
        verdict,
        amount: amountFromAccepts(challenge.accepts?.[0]),
        challenge,
        message: describeVerdict(verdict),
      };

    if (verdict.decision === DENY)
      return emit({ outcome: REFUSED, url, verdict, message: describeVerdict(verdict) });

    if (verdict.decision === ESCALATE)
      return emit({
        outcome: REQUIRES_CONFIRMATION,
        url,
        verdict,
        challenge,
        // Everything the approver UI needs to put a Grant on the device screen,
        // so the caller never has to re-parse the challenge to ask the question.
        ask: {
          mandateId,
          agent: mandate.message.agent,
          merchant: challenge.accepts[0].payTo,
          asset: mandate.message.asset,
          amount: amountFromAccepts(challenge.accepts[0]),
          resource: challenge.resource?.url ?? url,
        },
        message: describeVerdict(verdict),
      });

    if (verdict.decision !== ALLOW)
      return emit({ outcome: FAILED, url, code: "UNKNOWN_VERDICT", verdict });

    // --- 2. debit the budget BEFORE signing anything ---
    const accepted = challenge.accepts[0];
    const amount = amountFromAccepts(accepted);
    const reservation = ledger.reserve({
      mandateId,
      amount,
      caps: mandate.message,
      // Only pass the grant through to the enforcement point if the Guard
      // actually allowed on its strength. A grant attached to a payment that
      // was within the envelope anyway must not be burned.
      ...(verdict.code === "WITHIN_GRANT" ? { grantId: gid, grantAmount: amount } : {}),
    });
    if (!reservation.ok)
      return emit({
        outcome: REFUSED,
        url,
        verdict: {
          decision: DENY,
          code: reservation.code,
          detail: reservation.detail,
          message: "reservation refused",
        },
        message: `reserve refused: ${reservation.code}`,
      });

    // --- 3. sign, check, submit; release the reservation on any failure ---
    try {
      const payload = await (await getClient()).createPaymentPayload(challenge);

      // --- 3b. what was signed must be what was approved ---
      const match = sameAccept(payload?.accepted, accepted);
      if (!match.ok) {
        ledger.release(reservation.reservationId, { reason: `signed ${match.field} differs` });
        return emit({
          outcome: REFUSED,
          url,
          verdict: {
            decision: DENY,
            code: "SIGNED_TERMS_MISMATCH",
            detail: match,
            message: `the signed payment's ${match.field} differs from the approved one`,
          },
          message: `the signed payment's ${match.field} differs from the approved one`,
        });
      }

      const paid = await fetchImpl(url, {
        ...init,
        headers: { ...headers, [HEADERS.signature]: encodePaymentSignatureHeader(payload) },
      });

      if (!paid.ok) {
        ledger.release(reservation.reservationId, {
          reason: `merchant rejected: HTTP ${paid.status}`,
        });
        return emit({
          outcome: FAILED,
          url,
          code: "MERCHANT_REJECTED",
          status: paid.status,
          message: await safeText(paid),
        });
      }

      let settlement = null;
      const respHeader = paid.headers.get(HEADERS.response);
      if (respHeader) {
        try {
          settlement = decodePaymentResponseHeader(respHeader);
        } catch {
          // A malformed receipt does not unpay the payment: the authorization is
          // out there and the money moved. Record it, flag the receipt.
          settlement = { success: true, unverifiedReceipt: true };
        }
      }

      ledger.commit(reservation.reservationId, { txHash: settlement?.transaction ?? null });

      return emit({
        outcome: PAID,
        url,
        amount,
        txHash: settlement?.transaction ?? null,
        settlement,
        verdict,
        // The merchant's challenge exactly as sent: what the payment answered.
        paymentRequired: header,
        response: paid,
      });
    } catch (e) {
      ledger.release(reservation.reservationId, { reason: `error: ${e.message}` });
      return emit({ outcome: FAILED, url, code: "PAYMENT_ERROR", message: e.message });
    }
  }

  return {
    buy,
    mandateId,
    get audit() {
      return [...audit];
    },
    stats() {
      const byOutcome = {};
      for (const e of audit) byOutcome[e.outcome] = (byOutcome[e.outcome] ?? 0) + 1;
      return {
        ...ledger.snapshot(mandateId, { windowSeconds }),
        byOutcome,
        unattendedPayments: audit.filter((e) => e.outcome === PAID && !e.free).length,
      };
    },
  };
}

async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
