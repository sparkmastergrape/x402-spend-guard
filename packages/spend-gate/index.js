// spend-gate: the one entry point.
//
//   import { buildMandate, evaluate, SpendLedger, verdictEvents } from "./index.js";
//
// Everything here is safe to import with no device, no network and no keys:
// nothing runs at import time except module loading. `viem` is the only
// dependency pulled in (`ethers` loads lazily, inside createOnChainChecker).
//
// Deliberately NOT exported from here:
//   src/payer/index.js            the x402 payer; needs @x402/core and @x402/evm, so
//                                 import it by path (or "spend-gate/payer")
//   src/payer/mock-merchant.mjs   a local test merchant
//   src/device/                   the Ledger/Speculos approver; needs the optional
//                                 peers @ledgerhq/* and reflect-metadata, so import
//                                 it by path (or "spend-gate/device"), see README.md
//   src/demo/                     the prompt-injection corpus and runner

// ---- mandate: the EIP-712 envelope a human signs ----
export {
  DOMAIN_NAME,
  DOMAIN_VERSION,
  MANDATE_TYPES,
  buildDomain,
  buildMandate,
  assertWellFormed,
  hashMandate,
  mandateId,
  toSignerPayload,
  recoverMandateSigner,
  verifyMandate,
  describeMandate,
  rlusd,
  formatRlusd,
} from "./src/mandate/index.js";

// ---- grants: one device-signed yes for one payment ----
export {
  GRANT_DOMAIN_NAME,
  GRANT_DOMAIN_VERSION,
  GRANT_TYPES,
  MAX_RESOURCE_CHARS,
  DEFAULT_TTL_SECONDS,
  buildGrantDomain,
  buildGrant,
  assertGrantWellFormed,
  hashGrant,
  grantId,
  toGrantSignerPayload,
  verifyGrant,
  describeGrant,
  grantAmount,
} from "./src/mandate/grant.js";

// ---- guard: ALLOW / ESCALATE / DENY ----
export {
  ALLOW,
  ESCALATE,
  DENY,
  CODES,
  evaluate,
  amountFromAccepts,
  isAutonomous,
  describeVerdict,
} from "./src/guard/index.js";

// ---- spend ledger: reservations, caps, cumulative vouchers ----
export { SpendLedger, assertSingleWriter } from "./src/ledger-spend/index.js";

// ---- revocation: read fail-closed ----
export {
  createRevocationChecker,
  createOnChainChecker,
  REGISTRY_ABI,
  LIVE as REVOCATION_LIVE,
  CACHED as REVOCATION_CACHED,
  STALE as REVOCATION_STALE,
  UNREACHABLE as REVOCATION_UNREACHABLE,
  NEVER_READ as REVOCATION_NEVER_READ,
} from "./src/revocation/index.js";

// ---- receipts ----
export { buildReceiptChain, renderChainText } from "./src/receipts/index.js";
export { renderReceiptsHtml } from "./src/receipts/render.js";

// ---- audit events (agent-audit/1) ----
export {
  SCHEMA as AUDIT_SCHEMA,
  OUTCOMES as AUDIT_OUTCOMES,
  ACTORS as AUDIT_ACTORS,
  UNITS as AUDIT_UNITS,
  EVIDENCE as AUDIT_EVIDENCE,
  STAGES as AUDIT_STAGES,
  MAINNET_NETWORKS,
  EVM_TESTNET_NETWORK,
  SOFTWARE_SIGNER,
  EMULATOR_SIGNER,
  DEVICE_SIGNER,
  SIGNERS,
  AuditSchemaError,
  cleanSummary,
  makeEvent,
  makeRunId,
  invoiceIdFor,
  verdictEvents,
  envelope,
  validateEnvelope,
} from "./src/audit/index.js";

// ---- constants: the verified XRPL EVM Testnet values ----
export * as network from "./src/config/network.js";
