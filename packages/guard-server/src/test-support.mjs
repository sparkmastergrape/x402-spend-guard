// Shared fixture: a signed mandate, a local x402 merchant and a guard service.
// Test-only keys: well-known Anvil/Hardhat development keys, never used on any chain.

import { privateKeyToAccount } from "viem/accounts";
import { buildMandate, rlusd, network } from "spend-gate";
import { createMockMerchant } from "../../spend-gate/src/payer/mock-merchant.mjs";
import { createGuardService, toJson } from "./service.js";

export const AGENT_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
export const APPROVER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const agent = privateKeyToAccount(AGENT_KEY);
export const approver = privateKeyToAccount(APPROVER_KEY);
export const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
export const REGISTRY = "0x0000000000000000000000000000000000000001";
export const PRICE = rlusd("0.01");

export async function signedMandate(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const mandate = buildMandate({
    agent: agent.address,
    asset: network.RLUSD,
    merchant: MERCHANT,
    maxPerCall: rlusd("0.05"),
    maxPerWindow: rlusd("0.5"),
    windowSeconds: 3600,
    maxTotal: rlusd("2"),
    validFrom: now - 60,
    validUntil: now + 3600,
    purpose: "market-data",
    nonce: now,
    registry: REGISTRY,
    ...overrides,
  });
  const signature = await approver.signTypedData(mandate);
  return { mandate, signature, json: toJson({ mandate, signature }) };
}

/** What the approval device does with `grantToSign`. */
export async function signGrant(grantJson) {
  const { domain, types, primaryType, message } = grantJson;
  return approver.signTypedData({ domain, types, primaryType, message });
}

export async function fixture({ policy = {}, merchantFaults = {} } = {}) {
  const { mandate, signature } = await signedMandate();
  const merchant = createMockMerchant({ payTo: MERCHANT, agent: agent.address, price: PRICE, faults: merchantFaults });
  const { url } = await merchant.listen();
  const service = await createGuardService({
    mandate,
    mandateSignature: signature,
    approver: approver.address,
    signer: agent,
    policy,
  });
  return { service, merchant, url, mandate, signature };
}
