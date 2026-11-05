// Mandate — the EIP-712 spend envelope a human signs on a Ledger device.
//
// Pure: no network, no device, no keys. Everything here is unit-testable and is
// the part other projects would import.
//
// Field types are chosen for ON-DEVICE READABILITY, not on-wire compactness.
// The Ethereum app renders each field as "<name> | <value>", so a bytes32
// becomes two pages of hex that no human can check. Measured on the emulator.

import {
  hashTypedData,
  recoverTypedDataAddress,
  parseUnits,
  formatUnits,
  getAddress,
  isAddress,
} from "viem";
import { CHAIN_ID, RLUSD, RLUSD_DECIMALS } from "../config/network.js";

export const DOMAIN_NAME = "AgentSpendMandate";
export const DOMAIN_VERSION = "1";

export const MANDATE_TYPES = {
  Mandate: [
    { name: "agent", type: "address" },
    { name: "asset", type: "address" },
    { name: "merchant", type: "address" },
    { name: "maxPerCall", type: "uint256" },
    { name: "maxTotal", type: "uint256" },
    { name: "maxPerWindow", type: "uint256" },
    { name: "windowSeconds", type: "uint256" },
    { name: "validFrom", type: "uint64" },
    { name: "validUntil", type: "uint64" },
    { name: "purpose", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

const UINT_FIELDS = [
  "maxPerCall",
  "maxTotal",
  "maxPerWindow",
  "windowSeconds",
  "validFrom",
  "validUntil",
  "nonce",
];
const ADDRESS_FIELDS = ["agent", "asset", "merchant"];

export function buildDomain({ chainId = CHAIN_ID, registry }) {
  if (!registry || !isAddress(registry))
    throw new Error("buildDomain: registry must be an address (the verifyingContract)");
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId: Number(chainId),
    verifyingContract: getAddress(registry),
  };
}

/** Convert a human RLUSD figure to base units. Never hand-write the zeros. */
export const rlusd = (n) => parseUnits(String(n), RLUSD_DECIMALS);
/** Inverse, for display and for device-readable summaries. */
export const formatRlusd = (v) => formatUnits(BigInt(v), RLUSD_DECIMALS);

/**
 * Build a mandate. Amounts are in RLUSD base units (18 decimals); pass bigints
 * or decimal strings and they are normalised.
 */
export function buildMandate({
  agent,
  merchant,
  asset = RLUSD,
  maxPerCall,
  maxTotal,
  maxPerWindow,
  windowSeconds = 3600,
  validFrom,
  validUntil,
  purpose,
  nonce,
  chainId = CHAIN_ID,
  registry,
}) {
  const from = BigInt(validFrom ?? Math.floor(Date.now() / 1000));
  const mandate = {
    domain: buildDomain({ chainId, registry }),
    types: MANDATE_TYPES,
    primaryType: "Mandate",
    message: normalizeMessage({
      agent,
      asset,
      merchant,
      maxPerCall,
      maxTotal,
      maxPerWindow,
      windowSeconds,
      validFrom: from,
      validUntil: BigInt(validUntil ?? from + 3600n),
      purpose: String(purpose ?? ""),
      nonce: BigInt(nonce ?? from),
    }),
  };
  assertWellFormed(mandate);
  return mandate;
}

function normalizeMessage(m) {
  const out = { ...m };
  for (const f of ADDRESS_FIELDS) {
    if (!isAddress(out[f] ?? "")) throw new Error(`mandate.${f} is not an address: ${out[f]}`);
    out[f] = getAddress(out[f]);
  }
  for (const f of UINT_FIELDS) {
    if (out[f] === undefined || out[f] === null) throw new Error(`mandate.${f} is required`);
    out[f] = BigInt(out[f]);
    if (out[f] < 0n) throw new Error(`mandate.${f} must not be negative`);
  }
  out.purpose = String(out.purpose ?? "");
  return out;
}

/**
 * Structural invariants. These are bugs or nonsense, not policy decisions, so
 * they throw rather than producing a verdict.
 */
export function assertWellFormed(mandate) {
  const m = mandate.message;
  if (m.validUntil <= m.validFrom)
    throw new Error("mandate must expire after it starts (validUntil <= validFrom)");
  if (m.maxPerCall === 0n) throw new Error("maxPerCall of 0 authorises nothing");
  if (m.maxTotal < m.maxPerCall)
    throw new Error("maxTotal < maxPerCall — the first call could never succeed");
  if (m.maxPerWindow < m.maxPerCall)
    throw new Error("maxPerWindow < maxPerCall — the first call could never succeed");
  if (m.windowSeconds === 0n) throw new Error("windowSeconds of 0 makes maxPerWindow meaningless");
  if (!m.purpose.trim())
    throw new Error("purpose is required — a limit a human cannot read a reason for is not reviewable");
  // The device paginates long strings; keep purpose to one readable screen.
  if (m.purpose.length > 32) throw new Error("purpose must be <= 32 chars to stay readable on device");
  return true;
}

/** The EIP-712 digest. Doubles as the mandate's stable identifier. */
export function hashMandate(mandate) {
  return hashTypedData(mandate);
}
export const mandateId = hashMandate;

/**
 * The DMK signer takes plain JSON, so bigints must be stringified. viem's
 * hashing wants the bigints. One source of truth, converted at the boundary.
 */
export function toSignerPayload(mandate) {
  return {
    ...mandate,
    message: Object.fromEntries(
      Object.entries(mandate.message).map(([k, v]) => [
        k,
        typeof v === "bigint" ? v.toString() : v,
      ]),
    ),
  };
}

/** Recover the signer of a mandate. Returns a checksummed address. */
export async function recoverMandateSigner(mandate, signature) {
  return recoverTypedDataAddress({ ...mandate, signature });
}

/**
 * Verify a mandate was signed by `approver`.
 * Returns { ok, recovered, reason } — never throws on a bad signature, because
 * an invalid signature is an expected input, not an exceptional one.
 */
export async function verifyMandate(mandate, signature, approver) {
  let recovered;
  try {
    recovered = await recoverMandateSigner(mandate, signature);
  } catch (e) {
    return { ok: false, recovered: null, reason: `signature unrecoverable: ${e.message}` };
  }
  if (!approver) return { ok: true, recovered };
  const ok = recovered.toLowerCase() === String(approver).toLowerCase();
  return {
    ok,
    recovered,
    reason: ok ? null : `signed by ${recovered}, expected ${getAddress(approver)}`,
  };
}

/** Human-readable one-liner, for logs, receipts and the approver UI. */
export function describeMandate(mandate) {
  const m = mandate.message;
  return [
    `"${m.purpose}"`,
    `<= ${formatRlusd(m.maxPerCall)} RLUSD/call`,
    `<= ${formatRlusd(m.maxPerWindow)}/${m.windowSeconds}s`,
    `<= ${formatRlusd(m.maxTotal)} total`,
    `to ${m.merchant}`,
    `until ${new Date(Number(m.validUntil) * 1000).toISOString()}`,
  ].join(", ");
}
