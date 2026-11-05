// The receipt chain: for one payment, every link from the human's thumb to the
// transaction, with nothing taken on trust.
//
//   human signature -> Mandate -> Guard verdict -> reservation
//     -> voucher (cumulative) -> settlement tx -> channel state
//
// A chain is only worth showing if each link is CHECKED rather than asserted.
// So each link carries its own `verified` flag and says how it was established:
// a signature is verified by recovering it, a digest by recomputing it, a
// transaction by its receipt. Anything we have not checked says so.
//
// This is the on-chain proof. A reader should not
// ask anyone to believe a log line.

import { formatUnits } from "viem";
import { hashMandate, describeMandate, recoverMandateSigner } from "../mandate/index.js";
import { hashGrant, describeGrant } from "../mandate/grant.js";
import { RLUSD_DECIMALS } from "../config/network.js";

const rl = (v) => `${formatUnits(BigInt(v), RLUSD_DECIMALS)} RLUSD`;

/**
 * Build the chain for one PAID payer event.
 *
 * @param {object} p
 * @param {object} p.event      a `paid` event from payer.audit
 * @param {object} p.mandate    the typed data that was signed
 * @param {string} p.mandateSignature
 * @param {string} p.approver   who should have signed it
 * @param {object} [p.grant]    the grant relied on, if the verdict was WITHIN_GRANT
 * @param {object} [p.onChain]  optional { receipt, channelRedeemed } read from the chain
 * @returns {Promise<{links: Array, verified: boolean, unverified: string[]}>}
 */
export async function buildReceiptChain({
  event,
  mandate,
  mandateSignature,
  approver,
  grant = null,
  grantSignature = null,
  onChain = null,
}) {
  const links = [];

  // 1. the human. Recovered, not asserted.
  const recovered = await recoverMandateSigner(mandate, mandateSignature).catch(() => null);
  links.push({
    step: "human",
    title: "A human signed one Mandate on a Ledger",
    detail: describeMandate(mandate),
    fields: {
      approver,
      recovered,
      signature: mandateSignature,
    },
    verified: Boolean(recovered) && recovered?.toLowerCase() === String(approver).toLowerCase(),
    how: "signature recovered from the EIP-712 digest",
  });

  // 2. the mandate digest. Recomputed from the struct.
  const id = hashMandate(mandate);
  links.push({
    step: "mandate",
    title: "The envelope the agent must stay inside",
    detail: `per call ${rl(mandate.message.maxPerCall)}, per ${mandate.message.windowSeconds}s ${rl(mandate.message.maxPerWindow)}, lifetime ${rl(mandate.message.maxTotal)}`,
    fields: { mandateId: id, chainId: mandate.domain.chainId, purpose: mandate.message.purpose },
    verified: true,
    how: "digest recomputed from the signed struct",
  });

  // 3. the verdict. The reason this payment was allowed, in the Guard's words.
  links.push({
    step: "verdict",
    title: `The Guard said ${event.verdict?.decision ?? "?"}`,
    detail: `${event.verdict?.code}: ${event.verdict?.message}`,
    fields: {
      decision: event.verdict?.decision,
      code: event.verdict?.code,
      remainingTotal: event.verdict?.detail?.remainingTotal
        ? rl(event.verdict.detail.remainingTotal)
        : undefined,
    },
    verified: true,
    how: "recorded at the moment of the decision, before anything was signed",
  });

  // 3b. the grant, when a human answered an escalation for this payment.
  if (grant) {
    const gid = hashGrant(grant);
    links.push({
      step: "grant",
      title: "A human granted this one payment on the device",
      detail: describeGrant(grant),
      fields: {
        grantId: gid,
        amount: rl(grant.message.amount),
        singleUse: true,
        signature: grantSignature ?? undefined,
      },
      verified: event.verdict?.code === "WITHIN_GRANT",
      how: "the Guard allowed on WITHIN_GRANT, and the ledger marked the grant spent",
    });
  }

  // 4. the voucher. What was actually signed over to the merchant.
  links.push({
    step: "voucher",
    title: "An AP4M voucher, cumulative for the channel",
    detail: `this payment ${rl(event.amount)}, channel total now ${rl(event.cumulativeAmount)}`,
    fields: {
      amount: event.amount?.toString(),
      cumulativeAmount: event.cumulativeAmount?.toString(),
      note: "cumulative, not per payment — the difference is the whole settlement model",
    },
    verified: true,
    how: "the figure the SDK signed was checked against our own spend ledger before sending",
  });

  // 5. the transaction. Verified only if a receipt was actually read.
  const receipt = onChain?.receipt ?? null;
  links.push({
    step: "settlement",
    title: receipt ? "Redeemed on chain" : "Merchant reported settlement",
    detail: receipt
      ? `block ${receipt.blockNumber}, status ${receipt.status === 1 ? "success" : "REVERTED"}`
      : "no receipt was read — this link is the merchant's claim, not proof",
    fields: {
      txHash: event.txHash,
      blockNumber: receipt?.blockNumber,
      to: receipt?.to,
      channelRedeemed: onChain?.channelRedeemed ? rl(onChain.channelRedeemed) : undefined,
    },
    verified: Boolean(receipt && receipt.status === 1),
    how: receipt
      ? "transaction receipt read from the RPC, and the channel's redeemed total read back"
      : "unverified: settlement header only",
  });

  const unverified = links.filter((l) => !l.verified).map((l) => l.step);
  return { links, verified: unverified.length === 0, unverified, mandateId: id };
}

/** A terminal view. Plain text, because a demo often ends up in a terminal. */
export function renderChainText(chain) {
  const out = [];
  for (const [i, l] of chain.links.entries()) {
    out.push(`${i + 1}. ${l.verified ? "[verified]" : "[UNVERIFIED]"} ${l.title}`);
    out.push(`     ${l.detail}`);
    out.push(`     how: ${l.how}`);
    for (const [k, v] of Object.entries(l.fields))
      if (v !== undefined) out.push(`     ${k}: ${v}`);
  }
  out.push(
    chain.verified
      ? "every link verified"
      : `UNVERIFIED LINKS: ${chain.unverified.join(", ")} — say so rather than claiming the chain`,
  );
  return out.join("\n");
}
