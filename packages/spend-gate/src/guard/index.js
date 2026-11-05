// Guard — the policy layer the x402 SDKs deliberately leave out.
//
//   "Decide spending policy. Caps and allowlists are passed *into* this skill.
//    The policy engine that decides them is its own layer."  — x402-xrpl
//
// The Guard checks each quote, including its amount, against a human-signed
// envelope.
//
// PURE AND SYNCHRONOUS. No keys, no network, no model, no clock of its own.
// Everything it needs is an argument, which is what makes it testable without a
// device and reusable by any agent stack. An LLM cannot talk it out of a verdict.
//
// AUTONOMY IS THE POINT. ALLOW is the common verdict: the human signs one
// envelope, and everything inside it proceeds untouched. ESCALATE is the rare
// exception, not a confirm-on-every-payment dialog.

import { getAddress } from "viem";
import { X402_SCHEME, X402_NETWORK } from "../config/network.js";

export const ALLOW = "ALLOW";
export const ESCALATE = "ESCALATE";
export const DENY = "DENY";

/**
 * DENY  — structural or cryptographic failures. No human judgement could make
 *         these safe, so we never prompt: prompting on them would train the
 *         operator to rubber-stamp.
 * ESCALATE — a human is told and the payment is held. A single-use grant
 *         answers the quantitative ones (OVER_PER_CALL, OVER_TOTAL, OVER_WINDOW).
 *         It does NOT answer UNKNOWN_MERCHANT or MANDATE_EXPIRED: those are
 *         checked before a grant is looked at, so only a new Mandate resolves
 *         them. It never lifts OVER_CHANNEL_CAP (reserve() refuses it).
 */
export const CODES = {
  // DENY
  BAD_SIGNATURE: DENY,
  WRONG_APPROVER: DENY,
  REVOKED: DENY,
  CHAIN_MISMATCH: DENY,
  NETWORK_MISMATCH: DENY,
  ASSET_MISMATCH: DENY,
  AGENT_MISMATCH: DENY,
  LEDGER_MISMATCH: DENY,
  SCHEME_UNSUPPORTED: DENY,
  RESOURCE_MISMATCH: DENY,
  MALFORMED_CHALLENGE: DENY,
  CUMULATIVE_MISMATCH: DENY,
  CHANNEL_MISMATCH: DENY,
  MULTIPLE_ACCEPTS: DENY,
  NOT_YET_VALID: DENY,
  NON_POSITIVE_AMOUNT: DENY,
  // DENY — a grant that does not match what it is being used for is worse than
  // no grant at all: it means something is being replayed or substituted.
  GRANT_MISMATCH: DENY,
  GRANT_EXPIRED: DENY,
  GRANT_SPENT: DENY,
  BAD_GRANT_SIGNATURE: DENY,
  // ESCALATE
  OVER_PER_CALL: ESCALATE,
  OVER_TOTAL: ESCALATE,
  OVER_WINDOW: ESCALATE,
  OVER_CHANNEL_CAP: ESCALATE,
  UNKNOWN_MERCHANT: ESCALATE,
  MANDATE_EXPIRED: ESCALATE,
};

const verdict = (decision, code, detail, message) => ({ decision, code, detail, message });
const allow = (detail) => verdict(ALLOW, "WITHIN_MANDATE", detail, "within the signed envelope");
const allowByGrant = (detail) =>
  verdict(ALLOW, "WITHIN_GRANT", detail, "a human granted this one payment on the device");

/**
 * Read the price out of a 402 challenge entry.
 *
 * Confirmed from `@ap4m/sdk` types: `X402PaymentRequirements.amount` is a
 * decimal string. The other spellings are kept as a fallback for generic x402
 * servers. Fails closed if none is present — never defaults to zero.
 */
export function amountFromAccepts(accepted) {
  const raw =
    accepted?.amount ?? accepted?.maxAmountRequired ?? accepted?.value ?? accepted?.price;
  if (raw === undefined || raw === null) return null;
  try {
    const v = BigInt(raw);
    return v < 0n ? null : v;
  } catch {
    return null;
  }
}

const sameAddress = (a, b) => {
  try {
    return getAddress(a) === getAddress(b);
  } catch {
    return false;
  }
};

/**
 * Evaluate a 402 challenge against a signed mandate and a spend snapshot.
 *
 * @param {object} p
 * @param {object}  p.mandate        EIP-712 typed data (src/mandate)
 * @param {string}  p.mandateId      its digest
 * @param {boolean} p.signatureValid did the signature recover to the approver (resolved by the caller)
 * @param {boolean} [p.revoked]      revocation state, resolved by the caller (keeps this pure)
 * @param {object}  p.challenge      decoded PAYMENT-REQUIRED
 * @param {string}  [p.agent]        the paying agent address
 * @param {number}  p.now            unix seconds
 * @param {object}  p.spend          SpendLedger.snapshot() for this mandate
 * @param {bigint}  [p.channelCumulative] cumulative already claimed on the channel
 * @param {bigint}  [p.channelCap]
 * @param {object}  [p.grant]               a device-signed Grant for THIS payment (src/mandate/grant.js)
 * @param {string}  [p.grantId]             its digest
 * @param {boolean} [p.grantSignatureValid] resolved by the caller, like signatureValid
 * @param {boolean} [p.grantConsumed]       has this grant already been spent
 * @param {object}  [p.policy]
 * @returns {{decision:string, code:string, detail:object, message:string}}
 */
export function evaluate({
  mandate,
  mandateId,
  signatureValid,
  revoked = false,
  challenge,
  agent,
  now,
  spend,
  channelCumulative = 0n,
  channelCap,
  grant = null,
  grantId = null,
  grantSignatureValid = false,
  grantConsumed = false,
  policy = {},
}) {
  const {
    expectedNetwork = X402_NETWORK,
    allowedSchemes = [X402_SCHEME],
    expectedLedger,
    expectedResourceUrl,
    onUnknownMerchant = ESCALATE,
    expectedChannelId,
    // Listed price in the asset's base units (bigint or integer string), and how far
    // above it a 402 may go. Unset = no price-change check.
    expectedPrice,
    priceTolerancePct = 0,
  } = policy;

  const deny = (code, detail, message) => verdict(DENY, code, detail, message);
  const escalate = (code, detail, message) => verdict(ESCALATE, code, detail, message);

  // --- cryptographic trust first. Nothing else matters if this fails. ---
  if (!signatureValid)
    return deny("BAD_SIGNATURE", { mandateId }, "mandate signature did not verify");
  if (revoked) return deny("REVOKED", { mandateId }, "mandate has been revoked");

  const m = mandate?.message;
  if (!m) return deny("MALFORMED_CHALLENGE", {}, "mandate has no message");

  // --- the challenge is hostile input: a remote server choosing fields of a
  //     transaction we are about to sign. Validate before trusting anything. ---
  const accepts = challenge?.accepts;
  if (!Array.isArray(accepts) || accepts.length === 0)
    return deny("MALFORMED_CHALLENGE", { challenge }, "402 carried no accepts[]");
  if (accepts.length !== 1)
    return deny(
      "MULTIPLE_ACCEPTS",
      { count: accepts.length },
      "402 offered several options; refusing to choose",
    );

  const a = accepts[0];

  if (expectedResourceUrl && challenge?.resource?.url !== expectedResourceUrl)
    return deny(
      "RESOURCE_MISMATCH",
      { got: challenge?.resource?.url, want: expectedResourceUrl },
      "402 is for a different resource than we asked for",
    );

  if (!allowedSchemes.includes(a.scheme))
    return deny("SCHEME_UNSUPPORTED", { got: a.scheme, allowed: allowedSchemes }, "unsupported scheme");

  if (a.network !== expectedNetwork)
    return deny("NETWORK_MISMATCH", { got: a.network, want: expectedNetwork }, "wrong network");

  const chainFromNetwork = Number(String(expectedNetwork).split(":")[1]);
  if (Number(mandate.domain?.chainId) !== chainFromNetwork)
    return deny(
      "CHAIN_MISMATCH",
      { mandateChainId: mandate.domain?.chainId, network: expectedNetwork },
      "mandate was signed for a different chain",
    );

  if (expectedLedger && !sameAddress(a.extra?.ledger ?? "", expectedLedger))
    return deny(
      "LEDGER_MISMATCH",
      { got: a.extra?.ledger, want: expectedLedger },
      "402 points at a different payment ledger",
    );

  if (!sameAddress(a.asset ?? "", m.asset))
    return deny("ASSET_MISMATCH", { got: a.asset, want: m.asset }, "payment asset is not the mandated asset");

  if (agent && !sameAddress(agent, m.agent))
    return deny("AGENT_MISMATCH", { got: agent, want: m.agent }, "mandate was issued to a different agent");

  const amount = amountFromAccepts(a);
  if (amount === null)
    return deny("MALFORMED_CHALLENGE", { accepted: a }, "402 did not state a readable amount");
  if (amount <= 0n)
    return deny("NON_POSITIVE_AMOUNT", { amount }, "402 asked for a non-positive amount");

  // --- price change (ported from tripwire-dispatch PriceChangeGuard). A merchant may
  //     ask its listed price plus a tolerance, no more. A price hike between the
  //     listing the agent chose and the 402 it got is a bait-and-switch. ---
  if (expectedPrice !== undefined) {
    const listed = BigInt(expectedPrice);
    const maxAccepted = (listed * BigInt(100 + priceTolerancePct)) / 100n;
    if (amount > maxAccepted)
      return deny(
        "PRICE_CHANGED",
        { amount, listed, priceTolerancePct, maxAccepted },
        "402 asks more than the listed price plus tolerance",
      );
  }

  // --- validity window ---
  if (now < Number(m.validFrom))
    return deny(
      "NOT_YET_VALID",
      { now, validFrom: Number(m.validFrom) },
      "mandate is not valid yet — check the clock",
    );
  if (now >= Number(m.validUntil))
    return escalate(
      "MANDATE_EXPIRED",
      { now, validUntil: Number(m.validUntil) },
      "mandate has expired",
    );

  // --- scope: who may be paid. This is the prompt-injection boundary: the
  //     allowlist is inside the signed payload, so redirecting payment to an
  //     attacker cannot pass without a fresh human decision. ---
  if (!sameAddress(a.payTo ?? "", m.merchant)) {
    const d = { payTo: a.payTo, allowed: m.merchant };
    return onUnknownMerchant === DENY
      ? deny("UNKNOWN_MERCHANT", d, "payee is not the mandated merchant")
      : escalate("UNKNOWN_MERCHANT", d, "payee is not the mandated merchant");
  }

  // --- the merchant's claim about channel state is hostile input too.
  //
  // `extra.acceptedCumulativeAmount` is the running total the MERCHANT says has
  // been accepted on this channel. Vouchers are cumulative, so a merchant that
  // inflates this figure gets a voucher signed at a higher running total —
  // i.e. it collects the difference. We trust our own committed record and
  // refuse any challenge that disagrees with it.
  if (a.extra?.acceptedCumulativeAmount !== undefined) {
    let claimed;
    try {
      claimed = BigInt(a.extra.acceptedCumulativeAmount);
    } catch {
      return deny(
        "MALFORMED_CHALLENGE",
        { acceptedCumulativeAmount: a.extra.acceptedCumulativeAmount },
        "acceptedCumulativeAmount is not a number",
      );
    }
    if (claimed !== BigInt(channelCumulative))
      return deny(
        "CUMULATIVE_MISMATCH",
        { claimed, ours: BigInt(channelCumulative) },
        "merchant disagrees with our record of what this channel has paid",
      );
  }

  if (expectedChannelId && a.extra?.channelId && a.extra.channelId !== expectedChannelId)
    return deny(
      "CHANNEL_MISMATCH",
      { got: a.extra.channelId, want: expectedChannelId },
      "402 names a different payment channel",
    );

  // --- a grant, if one was offered for this exact payment.
  //
  // A grant is checked AFTER every structural test above and BEFORE the caps,
  // because that is precisely its scope: it answers a quantitative question a
  // human is entitled to answer, and it can never excuse a wrong chain, a wrong
  // asset or an unknown payee. Those already returned DENY and never reach here.
  //
  // Everything about the grant must match this payment exactly. A grant is for
  // one payment, so "close enough" is a replay.
  if (grant) {
    const g = grant.message ?? {};
    const mismatch = (field, got, want) =>
      deny("GRANT_MISMATCH", { field, got, want }, `grant does not match this payment: ${field}`);

    if (!grantSignatureValid)
      return deny("BAD_GRANT_SIGNATURE", { grantId }, "grant signature did not verify");
    if (grantConsumed)
      return deny("GRANT_SPENT", { grantId }, "that grant has already been used once");
    if (g.mandateId !== mandateId) return mismatch("mandateId", g.mandateId, mandateId);
    if (!sameAddress(g.agent ?? "", m.agent)) return mismatch("agent", g.agent, m.agent);
    if (!sameAddress(g.merchant ?? "", a.payTo)) return mismatch("merchant", g.merchant, a.payTo);
    if (!sameAddress(g.asset ?? "", m.asset)) return mismatch("asset", g.asset, m.asset);
    if (BigInt(g.amount) !== amount) return mismatch("amount", BigInt(g.amount), amount);
    if (challenge?.resource?.url && g.resource !== challenge.resource.url)
      return mismatch("resource", g.resource, challenge.resource.url);
    if (now >= Number(g.validUntil))
      return deny(
        "GRANT_EXPIRED",
        { now, validUntil: Number(g.validUntil) },
        "grant has expired — ask again rather than stretching an old yes",
      );

    return allowByGrant({
      amount,
      merchant: a.payTo,
      grantId,
      grantExpires: Number(g.validUntil),
    });
  }

  // --- quantitative caps. Mirrors SpendLedger.reserve(), which re-checks
  //     atomically; this pass exists so the agent gets a reasoned verdict
  //     BEFORE anything is reserved. reserve() remains the enforcement point. ---
  if (amount > BigInt(m.maxPerCall))
    return escalate(
      "OVER_PER_CALL",
      { amount, maxPerCall: BigInt(m.maxPerCall) },
      "price exceeds the per-call limit",
    );

  const spentTotal = BigInt(spend?.total ?? 0n);
  if (spentTotal + amount > BigInt(m.maxTotal))
    return escalate(
      "OVER_TOTAL",
      { spent: spentTotal, amount, maxTotal: BigInt(m.maxTotal) },
      "would exceed the mandate's lifetime budget",
    );

  const inWindow = BigInt(spend?.window ?? 0n);
  if (inWindow + amount > BigInt(m.maxPerWindow))
    return escalate(
      "OVER_WINDOW",
      {
        inWindow,
        amount,
        maxPerWindow: BigInt(m.maxPerWindow),
        windowSeconds: Number(m.windowSeconds),
      },
      "would exceed the rate limit for this window",
    );

  if (channelCap !== undefined) {
    const next = BigInt(channelCumulative) + amount;
    if (next > BigInt(channelCap))
      return escalate(
        "OVER_CHANNEL_CAP",
        { cumulativeAmount: next, channelCap: BigInt(channelCap) },
        "would exceed the on-chain channel cap",
      );
  }

  return allow({
    amount,
    merchant: m.merchant,
    remainingTotal: BigInt(m.maxTotal) - spentTotal - amount,
    remainingWindow: BigInt(m.maxPerWindow) - inWindow - amount,
  });
}

/** True when the verdict permits an automatic, unattended payment. */
export const isAutonomous = (v) => v.decision === ALLOW;

/** A compact line for the audit trail and the demo UI. */
export function describeVerdict(v) {
  return `${v.decision} [${v.code}] ${v.message}`;
}
