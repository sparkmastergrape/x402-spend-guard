// A Grant: one human decision, for one payment, signed on the device.
//
// The Mandate is the standing envelope. A Grant is what resolves a single
// ESCALATE — the agent hit a cap, stopped, and the human said yes to this
// payment and nothing else. It is deliberately NOT a raised Mandate: it
// authorises one exact amount to one exact payee, once, and expires in minutes.
//
// Why a separate struct rather than re-signing the Mandate with bigger numbers:
// a re-signed Mandate is a new standing authority, and the human who meant
// "yes, buy this one thing" would have granted a larger budget for the rest of
// the hour. The blast radius of a mistaken tap should be one payment.
//
// FIELD TYPES ARE CHOSEN FOR THE DEVICE SCREEN, as in the Mandate.
// The three things a human must read to make this decision —
//   amount | merchant | resource
// — are a formatted decimal, an address and a short string. `mandateId` is a
// bytes32 and renders as unreadable hex; it is in the struct for cryptographic
// binding, not for the human, and the device UI prompt we show alongside it
// carries the readable summary. Say that out loud rather than pretending the
// hex is meaningful to anyone.

import { parseUnits, formatUnits, hashTypedData, recoverTypedDataAddress, getAddress } from "viem";
import { CHAIN_ID, RLUSD_DECIMALS } from "../config/network.js";

export const GRANT_DOMAIN_NAME = "AgentSpendGrant";
export const GRANT_DOMAIN_VERSION = "1";

export const GRANT_TYPES = {
  Grant: [
    { name: "mandateId", type: "bytes32" },
    { name: "agent", type: "address" },
    { name: "merchant", type: "address" },
    { name: "asset", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "resource", type: "string" },
    { name: "validUntil", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
};

/** One screen's worth. A resource a human cannot read is not a control. */
export const MAX_RESOURCE_CHARS = 64;

/** Grants are short-lived by construction: a stale yes is not a yes. */
export const DEFAULT_TTL_SECONDS = 300;

export function buildGrantDomain({ chainId = CHAIN_ID, registry }) {
  if (!registry) throw new Error("buildGrantDomain: registry (verifyingContract) is required");
  return {
    name: GRANT_DOMAIN_NAME,
    version: GRANT_DOMAIN_VERSION,
    chainId: Number(chainId),
    verifyingContract: getAddress(registry),
  };
}

/**
 * @param {object} p
 * @param {string} p.mandateId   the mandate this tops up, bound cryptographically
 * @param {string} p.agent
 * @param {string} p.merchant    exact payee — never widened from the mandate
 * @param {string} p.asset
 * @param {bigint|string} p.amount  the exact amount authorised, base units
 * @param {string} p.resource    what is being bought, as the human sees it
 * @param {number} [p.validUntil]
 * @param {bigint|number} [p.nonce]
 * @param {string} p.registry
 */
export function buildGrant({
  mandateId,
  agent,
  merchant,
  asset,
  amount,
  resource,
  validUntil,
  nonce,
  registry,
  chainId = CHAIN_ID,
  now = Math.floor(Date.now() / 1000),
  ttlSeconds = DEFAULT_TTL_SECONDS,
}) {
  const grant = {
    domain: buildGrantDomain({ chainId, registry }),
    types: GRANT_TYPES,
    primaryType: "Grant",
    message: {
      mandateId,
      agent: getAddress(agent),
      merchant: getAddress(merchant),
      asset: getAddress(asset),
      amount: BigInt(amount),
      resource: String(resource),
      validUntil: BigInt(validUntil ?? now + ttlSeconds),
      nonce: BigInt(nonce ?? now),
    },
  };
  assertGrantWellFormed(grant);
  return grant;
}

export function assertGrantWellFormed(grant) {
  const m = grant?.message;
  if (!m) throw new Error("grant has no message");
  if (!/^0x[0-9a-fA-F]{64}$/.test(m.mandateId))
    throw new Error("grant mandateId must be a bytes32 hex string");
  if (BigInt(m.amount) <= 0n) throw new Error("grant amount must be positive");
  if (!m.resource) throw new Error("grant resource is required — the human must see what they buy");
  if (m.resource.length > MAX_RESOURCE_CHARS)
    throw new Error(
      `grant resource is ${m.resource.length} chars; keep it under ${MAX_RESOURCE_CHARS} so it fits one device screen`,
    );
  if (BigInt(m.validUntil) <= 0n) throw new Error("grant validUntil must be set");
  return grant;
}

export const hashGrant = (grant) => hashTypedData(grant);
export const grantId = hashGrant;

/** bigint-free copy for the device signer kit, same digest. */
export function toGrantSignerPayload(grant) {
  const message = {};
  for (const [k, v] of Object.entries(grant.message))
    message[k] = typeof v === "bigint" ? v.toString() : v;
  return { domain: grant.domain, types: grant.types, primaryType: grant.primaryType, message };
}

export async function verifyGrant(grant, signature, approver) {
  try {
    const recovered = await recoverTypedDataAddress({ ...grant, signature });
    const ok = recovered.toLowerCase() === String(approver).toLowerCase();
    return { ok, recovered, reason: ok ? null : `signed by ${recovered}, expected ${approver}` };
  } catch (e) {
    return { ok: false, recovered: null, reason: `unrecoverable signature: ${e.message}` };
  }
}

/** The line a human should be reading when they approve. */
export function describeGrant(grant) {
  const m = grant.message;
  return `pay ${formatUnits(BigInt(m.amount), RLUSD_DECIMALS)} once to ${m.merchant} for "${m.resource}", expires ${new Date(Number(m.validUntil) * 1000).toISOString()}`;
}

export const grantAmount = (n) => parseUnits(String(n), RLUSD_DECIMALS);
