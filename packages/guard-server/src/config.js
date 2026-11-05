// Build a guard service from environment variables, for the CLI.
//
//   GUARD_MANDATE_FILE   JSON file {"mandate": {...}, "signature": "0x..."}   required
//   GUARD_APPROVER       address that signed the mandate and signs Grants     required
//   AGENT_PRIVATE_KEY    0x-prefixed key of the agent wallet that pays         required
//   GUARD_POLICY         JSON object of extra Guard policy, e.g.
//                        {"expectedPrice":"10000000000000000","onUnknownMerchant":"DENY"}
//   GUARD_RPC_URL        RPC for the on-chain revocation registry. Without it,
//                        revocation is OFF and a warning is printed.
//   GUARD_HTTP_TOKEN     bearer token for the HTTP transport (16+ characters)
//
// AP2 mode (instead of GUARD_MANDATE_FILE; GUARD_APPROVER becomes optional):
//   GUARD_AP2_MANDATE_FILE    file holding the AP2 open Payment Mandate chain (compact)
//   GUARD_AP2_USER_JWK        the user's public key, EC P-256 JWK as JSON
//   GUARD_AP2_AGENT_JWK_FILE  private JWK of the mandate's cnf key; enables AP2 receipts
//   GUARD_AP2_ALLOW_UNCHECKED comma list of constraints to accept unchecked
//                             (only "payment.reference" is accepted)
//
// The agent key gives this process the power to pay. Keep the agent wallet's
// balance small: it is the real loss limit if the host is compromised.

import { readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { createOnChainChecker } from "spend-gate";
import { createGuardService, createAp2GuardService, mandateFromJson } from "./service.js";

function required(env, name) {
  const v = env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

function parsePolicy(raw) {
  if (!raw) return {};
  const p = JSON.parse(raw);
  if (typeof p !== "object" || p === null || Array.isArray(p)) throw new Error("GUARD_POLICY must be a JSON object");
  if (p.expectedPrice !== undefined) p.expectedPrice = BigInt(p.expectedPrice);
  return p;
}

const stderr = (m) => process.stderr.write(`${m}\n`);

async function revocationFromEnv(env, mandate, approver, warn) {
  if (!env.GUARD_RPC_URL || !approver) {
    warn("guard-server: revocation is OFF (it needs GUARD_RPC_URL and GUARD_APPROVER). A revoked mandate will still pay.");
    return null;
  }
  const { JsonRpcProvider } = await import("ethers");
  return createOnChainChecker({
    provider: new JsonRpcProvider(env.GUARD_RPC_URL),
    registry: mandate.domain.verifyingContract,
    approver,
  });
}

/**
 * @param {object} [env]   defaults to process.env
 * @param {object} [o]
 * @param {function} [o.warn]  where warnings go (stderr: stdout belongs to MCP)
 */
export async function serviceFromEnv(env = process.env, { warn = stderr } = {}) {
  if (env.GUARD_AP2_MANDATE_FILE) return ap2ServiceFromEnv(env, { warn });

  const file = JSON.parse(readFileSync(required(env, "GUARD_MANDATE_FILE"), "utf8"));
  if (!file.signature) throw new Error("GUARD_MANDATE_FILE has no `signature`");
  const mandate = mandateFromJson(file.mandate);
  const approver = required(env, "GUARD_APPROVER");
  const signer = privateKeyToAccount(required(env, "AGENT_PRIVATE_KEY"));
  if (signer.address.toLowerCase() !== mandate.message.agent.toLowerCase())
    throw new Error(`AGENT_PRIVATE_KEY is for ${signer.address}, but the mandate names agent ${mandate.message.agent}`);

  return createGuardService({
    mandate,
    mandateSignature: file.signature,
    approver,
    signer,
    policy: parsePolicy(env.GUARD_POLICY),
    revocation: await revocationFromEnv(env, mandate, approver, warn),
  });
}

async function ap2ServiceFromEnv(env, { warn }) {
  if (env.GUARD_MANDATE_FILE) throw new Error("set GUARD_MANDATE_FILE or GUARD_AP2_MANDATE_FILE, not both");
  const token = readFileSync(env.GUARD_AP2_MANDATE_FILE, "utf8").trim();
  const userJwk = JSON.parse(required(env, "GUARD_AP2_USER_JWK"));
  const agentPrivateJwk = env.GUARD_AP2_AGENT_JWK_FILE ? JSON.parse(readFileSync(env.GUARD_AP2_AGENT_JWK_FILE, "utf8")) : undefined;
  const allowUnchecked = (env.GUARD_AP2_ALLOW_UNCHECKED ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  const approver = env.GUARD_APPROVER || null;

  const service = await createAp2GuardService({
    ap2Token: token,
    userJwk,
    agentPrivateJwk,
    signer: privateKeyToAccount(required(env, "AGENT_PRIVATE_KEY")),
    allowUnchecked,
    approver,
    policy: parsePolicy(env.GUARD_POLICY),
  });

  // AP2 revocation is the user's credential provider's business; the on-chain
  // registry only knows EIP-712 mandates.
  warn("guard-server: AP2 mode has no revocation check. Keep the mandate's exp short.");
  if (!agentPrivateJwk) warn("guard-server: GUARD_AP2_AGENT_JWK_FILE is not set, so no AP2 receipts are signed.");
  if (!approver) warn("guard-server: GUARD_APPROVER is not set, so an escalation cannot be approved.");
  const { ap2 } = service.status();
  if (ap2.unchecked.length) warn(`guard-server: AP2 constraints accepted UNCHECKED: ${ap2.unchecked.join(", ")}`);
  return service;
}
