// Choosing a channel to demo on, deliberately.
//
// Both runners used to take `channels.find(c => c.channel_status === "open")` —
// the first open channel the service happened to list. With more than one open
// that is a coin toss, and we lost it: a channel with 0.024 RLUSD left was
// picked over one with 0.715, which would have stopped the demo after two calls
// with the cap doing exactly what it is supposed to do, at the worst moment.
//
// So: pick by on-chain headroom, not by list order, and refuse before the demo
// starts rather than halfway through it. A run that cannot finish should fail
// while there is still time to do something about it.

import { Contract, formatUnits } from "ethers";
import { PAYMENT_LEDGER, RLUSD_DECIMALS } from "../config/network.js";

const CHANNELS_ABI = [
  "function channels(bytes32 channelId) view returns (bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,address,uint64,uint8,address,uint64,address,uint64,uint64,uint64)",
];

/**
 * @param {object} p
 * @param {Array}  p.channels  as returned by /public/participant/channels
 * @param {object} p.provider  ethers provider
 * @param {bigint} p.need      total this run intends to spend, in base units
 * @param {number} [p.watchMs]  re-read the chosen channel after this long to catch a
 *                              concurrent payer; 0 skips the check
 * @returns {Promise<{channel, redeemed: bigint, capacity: bigint, headroom: bigint, candidates: Array}>}
 */
export async function chooseChannel({ channels, provider, need = 0n, watchMs = 4000 }) {
  const open = (channels ?? []).filter((c) => c.channel_status === "open");
  if (open.length === 0) {
    const seen = [...new Set((channels ?? []).map((c) => c.channel_status))].join(", ") || "none";
    throw new Error(`no OPEN channel (statuses seen: ${seen}) — open one with the AP4M kit`);
  }

  const ledger = new Contract(PAYMENT_LEDGER, CHANNELS_ABI, provider);
  const candidates = [];
  for (const channel of open) {
    const state = await ledger.channels(channel.channel_id);
    const capacity = BigInt(state[7]);
    const redeemed = BigInt(state[8]);
    candidates.push({ channel, capacity, redeemed, headroom: capacity - redeemed });
  }
  candidates.sort((a, b) => (b.headroom > a.headroom ? 1 : b.headroom < a.headroom ? -1 : 0));

  const best = candidates[0];

  // SINGLE WRITER. Vouchers are cumulative, so two payers on one channel race:
  // whoever signs the lower total loses, and the merchant's redemption reverts
  // with an error that names neither the total nor the cause. One sample cannot
  // prove nobody else is writing, but a second one a few seconds later catches
  // the case that matters — a demo running somewhere else right now — before we
  // start rather than three calls in.
  if (watchMs > 0) {
    await new Promise((r) => setTimeout(r, watchMs));
    const again = BigInt((await ledger.channels(best.channel.channel_id))[8]);
    if (again !== best.redeemed)
      throw new Error(
        `channel ${best.channel.channel_id} moved from ` +
          `${formatUnits(best.redeemed, RLUSD_DECIMALS)} to ${formatUnits(again, RLUSD_DECIMALS)} ` +
          `RLUSD redeemed in ${watchMs}ms with nothing from us — another payer is live on it with ` +
          `the same agent key. Cumulative vouchers allow one writer per channel: stop the other ` +
          `process first.`,
      );
  }

  if (need > 0n && best.headroom < need)
    throw new Error(
      `the roomiest open channel has ${formatUnits(best.headroom, RLUSD_DECIMALS)} RLUSD left, ` +
        `this run needs ${formatUnits(need, RLUSD_DECIMALS)}. ` +
        `Refusing to start a run that cannot finish — list them with the AP4M kit.`,
    );
  return { ...best, candidates };
}

/** One line per open channel, roomiest first, so the choice is visible. */
export function describeChoice({ candidates }, chosenId) {
  const u = (v) => formatUnits(v, RLUSD_DECIMALS);
  return candidates
    .map(
      (c) =>
        `  ${c.channel.channel_id === chosenId ? "->" : "  "} ${c.channel.channel_id.slice(0, 18)}…  ` +
        `cap ${u(c.capacity).padEnd(6)} redeemed ${u(c.redeemed).padEnd(10)} left ${u(c.headroom)}`,
    )
    .join("\n");
}
