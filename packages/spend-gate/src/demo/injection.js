// Running the attacks for real.
//
// Each scene is executed against the actual stack — the real Guard, the real
// spend ledger, the real payer, a merchant speaking the real AP4M wire format
// through the SDK's own codecs. Nothing is simulated except the agent's
// judgement, which is assumed absent.
//
// Exported rather than inlined in the demo script so the test suite runs the
// same code the demo does. A demo that passes while the tests exercise
// something else is a demo that will fail on stage.

import { Wallet } from "ethers";
import { privateKeyToAccount } from "viem/accounts";

import { buildMandate, rlusd, hashMandate } from "../mandate/index.js";
import { buildGrant, verifyGrant } from "../mandate/grant.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { createMockMerchant } from "../payer/mock-merchant.mjs";
import { createPayer, PAID } from "../payer/index.js";
import { createRevocationChecker } from "../revocation/index.js";
import { RLUSD } from "../config/network.js";

// Test keys from the standard Hardhat/anvil mnemonic. They hold nothing, on any
// chain, and nothing in this file touches a network.
const APPROVER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ATTACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const REGISTRY = "0x0000000000000000000000000000000000000001";
const PRICE = rlusd("0.01");
const MAX_PER_CALL = rlusd("0.05");
const MAX_STALE_MS = 15_000;

/**
 * One scene, start to finish. Returns what happened; the caller decides how to
 * narrate it, and the test asserts on the same object.
 */
export async function runScene(scene) {
  const approver = privateKeyToAccount(APPROVER_KEY);
  const attacker = privateKeyToAccount(ATTACKER_KEY);
  const agentSigner = Wallet.createRandom();
  const now = Math.floor(Date.now() / 1000);

  const mandate = buildMandate({
    agent: agentSigner.address,
    asset: RLUSD,
    merchant: MERCHANT,
    maxPerCall: MAX_PER_CALL,
    maxPerWindow: rlusd("0.5"),
    windowSeconds: 3600,
    maxTotal: rlusd("1"),
    validFrom: now - 60,
    validUntil: now + 3600,
    purpose: "market-data",
    nonce: now,
    registry: REGISTRY,
  });
  const mandateId = hashMandate(mandate);

  const merchant = createMockMerchant({
    payTo: MERCHANT,
    agent: agentSigner.address,
    price: PRICE,
  });
  const { url } = await merchant.listen();
  const ledger = new SpendLedger();

  // The registry reads fine until a scene breaks it. `skew` lets the
  // revocation scene move time forward instead of sleeping, because what
  // matters there is not that the read failed but that the last good read went
  // stale while it kept failing.
  const registry = { down: false, skew: 0 };
  const revocation = createRevocationChecker({
    read: async () => {
      if (registry.down) throw new Error("RPC unreachable");
      return false;
    },
    approver: approver.address,
    maxStaleMs: MAX_STALE_MS,
    clock: () => Date.now() + registry.skew,
  });

  const payer = createPayer({
    mandate,
    signatureValid: true,
    ledger,
    signer: agentSigner,
    revocation,
    // A scene may state the listed price. A quote above it is refused even inside every cap.
    policy: scene.effect.listedPrice ? { expectedPrice: rlusd(scene.effect.listedPrice) } : {},
  });

  try {
    // An honest payment first, so each scene shows a working system being
    // attacked rather than a system that never worked.
    const baseline = await payer.buy(url);
    if (baseline.outcome !== PAID)
      throw new Error(`baseline payment failed: ${baseline.message ?? baseline.verdict?.code}`);

    // --- the agent reads the document and obeys it ---
    const e = scene.effect;
    if (e.payTo) merchant.setFault("payTo", e.payTo);
    if (e.amount) merchant.setFault("amount", rlusd(e.amount));
    if (e.network) merchant.setFault("network", e.network);
    if (e.asset) merchant.setFault("asset", e.asset);

    let grant = null;
    let grantSignatureValid = false;
    let grantedPayments = 0;

    if (e.forgeGrant || e.replayGrant) {
      grant = buildGrant({
        mandateId,
        agent: agentSigner.address,
        merchant: MERCHANT,
        asset: RLUSD,
        amount: rlusd(e.amount),
        resource: url,
        registry: REGISTRY,
      });
    }

    if (e.forgeGrant) {
      // The attacker signs their own "approval". Every field in it is correct
      // except who signed it, which is the only field that matters. We resolve
      // it exactly as the real approver UI does — recover and compare — so the
      // `false` below is computed, not asserted.
      const signature = await attacker.signTypedData({
        domain: grant.domain,
        types: grant.types,
        primaryType: grant.primaryType,
        message: grant.message,
      });
      grantSignatureValid = (await verifyGrant(grant, signature, approver.address)).ok;
      if (grantSignatureValid)
        throw new Error("a grant signed by the attacker verified against the approver");
    }

    if (e.replayGrant) {
      // A genuine approval, genuinely signed, genuinely used once.
      const signature = await approver.signTypedData({
        domain: grant.domain,
        types: grant.types,
        primaryType: grant.primaryType,
        message: grant.message,
      });
      const check = await verifyGrant(grant, signature, approver.address);
      if (!check.ok) throw new Error(`the approver's own grant did not verify: ${check.reason}`);
      grantSignatureValid = true;

      const first = await payer.buy(url, { grant, grantSignatureValid });
      if (first.outcome !== PAID)
        throw new Error(`the genuine grant should have paid once: ${first.message}`);
      grantedPayments++;
    }

    if (e.breakRevocation) {
      registry.down = true;
      registry.skew = MAX_STALE_MS + 1_000;
    }

    const paymentsBefore = merchant.stats().redemptions.length;
    const result = await payer.buy(url, { grant, grantSignatureValid });
    const paymentsAfter = merchant.stats().redemptions.length;

    return {
      scene,
      paid: result.outcome === PAID,
      outcome: result.outcome,
      code: result.verdict?.code ?? result.code ?? null,
      decision: result.verdict?.decision ?? null,
      message: result.message,
      detail: result.verdict?.detail,
      // The claim worth checking is not "the Guard printed a refusal" but
      // "no voucher reached the merchant". These two numbers are that claim.
      merchantPaymentsBefore: paymentsBefore,
      merchantPaymentsAfter: paymentsAfter,
      honestPayments: 1 + grantedPayments,
      spent: ledger.snapshot(mandateId, { windowSeconds: 3600 }).total,
      mandateId,
    };
  } finally {
    await merchant.close();
  }
}

export async function runAllScenes(scenes) {
  const out = [];
  for (const s of scenes) out.push(await runScene(s));
  return out;
}
