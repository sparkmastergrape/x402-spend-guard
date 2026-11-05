// Revocation — reading the brake, and failing closed when we cannot.
//
// THE WHOLE POINT OF THIS FILE IS THE FAILURE PATH.
//
// A revocation check that answers "false" when the RPC is down is not a check.
// It is the opposite: the one moment a human most wants spending to stop — they
// have just revoked, perhaps because the agent is misbehaving — is exactly when
// a flaky answer must not read as "not revoked". So:
//
//   known not revoked, fresh   -> spend
//   known revoked              -> stop, permanently
//   unknown / stale / error    -> STOP, and say which
//
// The cost of that choice is honest and worth stating: a network outage stops
// an agent that was doing nothing wrong. That is the right way round for money.
// `maxStaleMs` is the dial, and `allowStaleWhenOffline` exists only so a
// deployment that genuinely prefers availability has to write that down.
//
// "our backend lies about revocation" is answered by the
// registry being on-chain and independently readable — but only if the verifier
// actually reads it, and treats "could not read" as "do not spend".

/** Why a mandate is considered revoked, or why we cannot say it is not. */
export const LIVE = "live"; // read from chain just now
export const CACHED = "cached"; // read recently, within maxStaleMs
export const STALE = "stale"; // last read too old to rely on
export const UNREACHABLE = "unreachable"; // the chain could not be read at all
export const NEVER_READ = "never-read"; // no successful read has happened yet

/**
 * @param {object} p
 * @param {(approver:string, mandateId:string) => Promise<boolean>} p.read
 *        reads the registry. Injected, so the Guard's behaviour under a dead
 *        RPC is a unit test and not a story.
 * @param {string} p.approver   the only approver whose revocations matter to us
 * @param {number} [p.maxStaleMs] how old a cached "not revoked" may be (default 15s)
 * @param {boolean} [p.allowStaleWhenOffline] prefer availability over safety (default false)
 * @param {() => number} [p.clock]
 */
export function createRevocationChecker({
  read,
  approver,
  maxStaleMs = 15_000,
  allowStaleWhenOffline = false,
  clock = () => Date.now(),
  onEvent = () => {},
}) {
  /** @type {Map<string, {revoked: boolean, at: number}>} */
  const cache = new Map();
  /** Once revoked, always revoked — never re-read, never un-cached. */
  const revoked = new Set();
  let lastError = null;

  /**
   * @returns {Promise<{revoked: boolean, source: string, detail?: object}>}
   *   `revoked: true` means do not spend — whether because it IS revoked or
   *   because we could not find out. `source` says which, and the caller
   *   should surface it: "stopped because revoked" and "stopped because the
   *   chain is unreachable" need different human responses.
   */
  async function check(mandateId) {
    if (revoked.has(mandateId)) return { revoked: true, source: CACHED };

    const now = clock();
    try {
      const isRevoked = await read(approver, mandateId);
      cache.set(mandateId, { revoked: Boolean(isRevoked), at: now });
      if (isRevoked) {
        revoked.add(mandateId);
        onEvent({ kind: "revoked", mandateId, approver });
        return { revoked: true, source: LIVE };
      }
      lastError = null;
      return { revoked: false, source: LIVE };
    } catch (e) {
      lastError = e;
      const seen = cache.get(mandateId);
      const age = seen ? now - seen.at : null;

      if (!seen) {
        onEvent({ kind: "fail-closed", mandateId, reason: NEVER_READ, error: e.message });
        return {
          revoked: true,
          source: NEVER_READ,
          detail: { error: e.message, message: "never read the registry — refusing to spend" },
        };
      }
      if (age <= maxStaleMs) {
        return { revoked: seen.revoked, source: CACHED, detail: { ageMs: age } };
      }
      if (allowStaleWhenOffline) {
        onEvent({ kind: "stale-allowed", mandateId, ageMs: age });
        return {
          revoked: seen.revoked,
          source: STALE,
          detail: { ageMs: age, message: "allowStaleWhenOffline is set — availability over safety" },
        };
      }
      onEvent({ kind: "fail-closed", mandateId, reason: UNREACHABLE, ageMs: age });
      return {
        revoked: true,
        source: UNREACHABLE,
        detail: {
          ageMs: age,
          maxStaleMs,
          error: e.message,
          message: "registry unreachable and the last read is too old — refusing to spend",
        },
      };
    }
  }

  return {
    check,
    /** Synchronous view for the Guard, which is pure and cannot await. */
    isRevokedSync: (mandateId) => revoked.has(mandateId),
    /** Pre-warm before a run of payments, so each payment is a cache read. */
    prime: (mandateId) => check(mandateId),
    get lastError() {
      return lastError;
    },
    snapshot: () => ({
      cached: cache.size,
      revoked: [...revoked],
      lastError: lastError?.message ?? null,
    }),
  };
}

/** The registry ABI, as little of it as a verifier needs. */
export const REGISTRY_ABI = [
  "function isRevoked(address approver, bytes32 mandateId) view returns (bool)",
  "function areRevoked(address approver, bytes32[] mandateIds) view returns (bool[])",
  "function revokedAt(address approver, bytes32 mandateId) view returns (uint256)",
  "function revocationDigest(bytes32 mandateId, address approver, uint256 nonce) view returns (bytes32)",
  "function revoke(bytes32 mandateId, address approver, uint256 nonce, bytes signature)",
  "function nonceUsed(address approver, uint256 nonce) view returns (bool)",
  "event Revoked(address indexed approver, bytes32 indexed mandateId, uint256 nonce, uint256 timestamp, address relayer)",
];

/**
 * A checker backed by the real contract.
 *
 * Note what is NOT here: no retry, no fallback RPC, no "if it fails, assume
 * fine". A read either worked or it did not, and `createRevocationChecker`
 * decides what that means.
 */
export function createOnChainChecker({ provider, registry, approver, ...opts }) {
  if (!registry)
    throw new Error(
      "createOnChainChecker: no registry address — deploy contracts/MandateRegistry.sol and pass its address, rather than running without revocation",
    );
  // Lazy so this module stays importable without ethers for the pure tests.
  let contract = null;
  const read = async (who, mandateId) => {
    if (!contract) {
      const { Contract } = await import("ethers");
      contract = new Contract(registry, REGISTRY_ABI, provider);
    }
    return contract.isRevoked(who, mandateId);
  };
  return createRevocationChecker({ read, approver, ...opts });
}
