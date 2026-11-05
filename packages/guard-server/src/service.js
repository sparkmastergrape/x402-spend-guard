// The guard service: one mandate, one spend ledger, one payer, and the four
// operations both transports expose (MCP in ./mcp.js, HTTP in ./http.js).
//
// The point of running the Guard as a service is that the agent never holds a
// path to money that skips it. The agent asks for a URL; the service fetches it,
// and pays only if the Guard allows. An escalation comes back as a question with
// the exact Grant a human must sign, and the agent retries with that signed Grant.
//
// Everything that leaves this module is plain JSON: bigints become decimal
// strings, and fetch Response objects are reduced to status and body text.

import {
  SpendLedger,
  verifyMandate,
  hashMandate,
  describeMandate,
  buildGrant,
  verifyGrant,
  buildMandate,
  network,
} from "spend-gate";
import { createPayer, PAID, REQUIRES_CONFIRMATION, REFUSED } from "spend-gate/payer";
import {
  verifyOpenPaymentMandate,
  toGuardMandate,
  signClosedPaymentMandate,
  transactionIdForChallenge,
  x402Instrument,
} from "spend-gate/ap2";
import { randomBytes } from "node:crypto";

/** Longest response body returned to the agent, in characters. */
export const MAX_BODY_CHARS = 65_536;

/** Rebuild a mandate from JSON, where every uint is a decimal string. */
export function mandateFromJson(json) {
  const m = typeof json === "string" ? JSON.parse(json) : json;
  if (!m?.message || !m?.domain) throw new Error("mandate JSON needs `domain` and `message`");
  return buildMandate({
    ...m.message,
    chainId: m.domain.chainId,
    registry: m.domain.verifyingContract,
  });
}

/** Rebuild a Grant from JSON, where every uint is a decimal string. */
export function grantFromJson(json) {
  const g = typeof json === "string" ? JSON.parse(json) : json;
  if (!g?.message || !g?.domain) throw new Error("grant JSON needs `domain` and `message`");
  return buildGrant({
    ...g.message,
    chainId: g.domain.chainId,
    registry: g.domain.verifyingContract,
  });
}

/** Deep copy with bigints as decimal strings. Drops values JSON cannot carry. */
export function toJson(value) {
  return JSON.parse(JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
}

async function bodyText(response, max) {
  if (!response) return null;
  try {
    const text = await response.text();
    return text.length > max ? `${text.slice(0, max)}…[truncated ${text.length - max} chars]` : text;
  } catch {
    return null;
  }
}

function assertHttpUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`not a URL: ${url}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:")
    throw new Error(`only http and https URLs are allowed, got ${u.protocol}`);
  return u.toString();
}

/**
 * @param {object} cfg
 * @param {object} cfg.mandate            EIP-712 mandate (from buildMandate or mandateFromJson)
 * @param {string} cfg.mandateSignature   the approver's signature over the mandate
 * @param {string} cfg.approver           address that must have signed the mandate and every Grant
 * @param {object} cfg.signer             agent signer (viem account or ethers-style signer)
 * @param {object} [cfg.policy]           extra Guard policy (expectedPrice, onUnknownMerchant, …)
 * @param {object} [cfg.revocation]       a checker from spend-gate's revocation module
 * @param {object} [cfg.ledger]           SpendLedger (default: a new in-memory one)
 * @param {function} [cfg.fetchImpl]
 * @param {function} [cfg.onEvent]        audit sink
 * @param {number} [cfg.maxBodyChars]
 * @param {object} [cfg.ap2]              internal: set by createAp2GuardService
 */
export async function createGuardService({
  mandate,
  mandateSignature,
  approver,
  signer,
  policy = {},
  revocation = null,
  ledger = new SpendLedger(),
  fetchImpl = globalThis.fetch,
  onEvent = () => {},
  maxBodyChars = MAX_BODY_CHARS,
  ap2 = null,
}) {
  if (!ap2) {
    if (!approver) throw new Error("approver address is required");
    const check = await verifyMandate(mandate, mandateSignature, approver);
    if (!check.ok) throw new Error(`mandate signature does not verify: ${check.reason}`);
  }

  const mandateId = hashMandate(mandate);
  const registry = mandate.domain.verifyingContract;
  const chainId = mandate.domain.chainId;
  const payer = createPayer({
    mandate,
    signatureValid: true,
    ledger,
    signer,
    policy,
    revocation,
    fetchImpl,
    onEvent,
  });

  let paidCount = 0;
  let inFlight = 0;

  /** AP2's own record of a settled payment: a closed Payment Mandate signed by the agent. */
  async function ap2Receipt(target, r) {
    if (!ap2.agentPrivateJwk) return { ap2PaymentMandate: null };
    try {
      const { token } = await signClosedPaymentMandate({
        openToken: ap2.token,
        agentPrivateJwk: ap2.agentPrivateJwk,
        payee: ap2.payee,
        amount: r.amount,
        scale: ap2.scale,
        currency: ap2.currency,
        instrument: ap2.instrument,
        transactionId: transactionIdForChallenge(r.paymentRequired ?? ""),
        aud: new URL(target).origin,
        nonce: randomBytes(16).toString("hex"),
      });
      return { ap2PaymentMandate: token };
    } catch (e) {
      // The payment settled. A receipt that cannot be written does not undo it.
      return { ap2PaymentMandate: null, ap2Problem: e.message };
    }
  }

  /** The Grant a human must sign to approve exactly this escalated payment. */
  const grantToSign = (ask) => toJson(buildGrant({ ...ask, registry, chainId }));

  async function resolveGrant(grant, grantSignature) {
    if (!grant) return { grant: null, grantSignatureValid: false };
    if (!approver) return { grant: null, grantSignatureValid: false, grantCheck: { reason: "no approver is configured, so no Grant can be accepted" } };
    const g = grantFromJson(grant);
    const v = await verifyGrant(g, grantSignature, approver);
    return { grant: g, grantSignatureValid: v.ok, grantCheck: v };
  }

  /**
   * Fetch `url`. Pay over x402 if, and only if, the Guard allows.
   * A refusal or an escalation is a result, not an error.
   */
  async function pay({ url, method = "GET", headers = {}, body, grant, grantSignature } = {}) {
    const target = assertHttpUrl(url);
    const g = await resolveGrant(grant, grantSignature);
    const init = { method, headers: { ...headers } };
    if (body !== undefined && method !== "GET" && method !== "HEAD") init.body = body;

    // AP2 without agent_recurrence: the mandate pays once. In-flight payments
    // count, so two concurrent calls cannot both pass.
    if (ap2?.maxPayments != null && paidCount + inFlight >= ap2.maxPayments)
      return toJson({
        outcome: REFUSED,
        url: target,
        code: "AP2_SINGLE_USE",
        message: `the AP2 mandate allows ${ap2.maxPayments} payment(s) and has no agent_recurrence`,
        verdict: null,
      });

    inFlight++;
    let r;
    try {
      r = await payer.buy(target, {
        init,
        grant: g.grant,
        grantSignatureValid: g.grantSignatureValid,
      });
    } finally {
      inFlight--;
    }
    if (r.outcome === PAID && !r.free) paidCount++;

    const out = {
      outcome: r.outcome,
      url: target,
      message: r.message ?? null,
      code: r.code ?? r.verdict?.code ?? null,
      verdict: r.verdict ?? null,
    };
    if (grant && !g.grantSignatureValid) out.grantProblem = g.grantCheck?.reason ?? "grant signature invalid";
    if (r.outcome === PAID) {
      out.free = Boolean(r.free);
      out.amount = r.amount ?? null;
      out.txHash = r.txHash ?? null;
      out.status = r.response?.status ?? r.status ?? null;
      out.body = await bodyText(r.response, maxBodyChars);
      if (ap2 && !r.free) Object.assign(out, await ap2Receipt(target, r));
    } else if (r.status !== undefined) {
      out.status = r.status;
    }
    if (r.outcome === REQUIRES_CONFIRMATION) {
      out.ask = r.ask;
      out.grantToSign = grantToSign(r.ask);
    }
    return toJson(out);
  }

  /** The verdict a payment for `url` would get now. Reserves, signs and records nothing. */
  async function checkPayment({ url, method = "GET", headers = {} } = {}) {
    const target = assertHttpUrl(url);
    const r = await payer.buy(target, { init: { method, headers: { ...headers } }, dryRun: true });
    const out = {
      outcome: r.outcome,
      url: target,
      free: Boolean(r.free),
      amount: r.amount ?? null,
      code: r.code ?? r.verdict?.code ?? null,
      verdict: r.verdict ?? null,
      message: r.message ?? null,
    };
    if (r.response) await bodyText(r.response, 0); // drain the free response
    return toJson(out);
  }

  function status() {
    return toJson({
      mandateId,
      mandate: describeMandate(mandate),
      agent: mandate.message.agent,
      merchant: mandate.message.merchant,
      asset: mandate.message.asset,
      caps: {
        maxPerCall: mandate.message.maxPerCall,
        maxPerWindow: mandate.message.maxPerWindow,
        windowSeconds: mandate.message.windowSeconds,
        maxTotal: mandate.message.maxTotal,
        validUntil: mandate.message.validUntil,
      },
      spend: payer.stats(),
      ...(ap2
        ? {
            ap2: {
              currency: ap2.currency,
              maxPayments: ap2.maxPayments,
              paymentsMade: paidCount,
              unchecked: ap2.unchecked,
              constraints: ap2.open.constraints,
              receipts: Boolean(ap2.agentPrivateJwk),
            },
          }
        : {}),
    });
  }

  function audit({ limit = 100 } = {}) {
    const events = payer.audit.slice(-Math.max(1, Math.min(1000, Number(limit) || 100)));
    return toJson(events.map(({ response: _r, challenge: _c, ...e }) => e));
  }

  return { pay, checkPayment, status, audit, mandateId };
}

/**
 * A guard service whose mandate is an AP2 v0.2 open Payment Mandate signed by
 * the user, instead of an EIP-712 mandate. Constraints the Guard cannot enforce
 * exactly are refused at startup (spend-gate/ap2).
 *
 * @param {object} cfg
 * @param {string} cfg.ap2Token          the open Payment Mandate chain
 * @param {object} cfg.userJwk           the user's public key (EC P-256 JWK)
 * @param {object} cfg.signer            the agent's EVM signer (pays the x402 authorizations)
 * @param {object} [cfg.agentPrivateJwk] private half of the mandate's cnf.jwk; enables AP2 receipts
 * @param {string} [cfg.registry]        EIP-712 domain of the derived mandate
 * @param {string[]} [cfg.allowUnchecked]
 * @param {string} [cfg.approver]        optional: lets a human approve an escalation with a Grant
 */
export async function createAp2GuardService({ ap2Token, userJwk, signer, agentPrivateJwk, registry, allowUnchecked = [], approver = null, ...rest }) {
  const { open, agentJwk } = await verifyOpenPaymentMandate(ap2Token, userJwk);
  if (agentPrivateJwk && (agentPrivateJwk.x !== agentJwk.x || agentPrivateJwk.y !== agentJwk.y))
    throw new Error("the AP2 agent key does not match the mandate's cnf.jwk");
  const agent = signer.address ?? (await signer.getAddress());
  const t = toGuardMandate(open, { agent, registry: registry ?? network.MANDATE_REGISTRY, allowUnchecked });
  const payee = open.constraints.find((c) => c.type === "payment.allowed_payees").allowed[0];
  return createGuardService({
    ...rest,
    mandate: t.mandate,
    approver,
    signer,
    ap2: {
      token: ap2Token,
      open,
      agentPrivateJwk,
      currency: t.currency,
      scale: t.scale,
      maxPayments: t.maxPayments,
      unchecked: t.unchecked,
      payee,
      instrument: x402Instrument({ chainId: t.mandate.domain.chainId, asset: t.mandate.message.asset }),
    },
  });
}
