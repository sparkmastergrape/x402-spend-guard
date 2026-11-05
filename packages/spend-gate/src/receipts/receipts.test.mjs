// The receipt chain must not flatter itself. These tests are mostly about the
// `verified` flag telling the truth, because a view that makes a merchant's
// claim look like on-chain proof is worse than no view.

import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";

import { buildMandate, rlusd, hashMandate } from "../mandate/index.js";
import { buildGrant } from "../mandate/grant.js";
import { buildReceiptChain, renderChainText } from "./index.js";
import { renderReceiptsHtml } from "./render.js";
import { RLUSD } from "../config/network.js";

const approver = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const other = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const REGISTRY = "0x0000000000000000000000000000000000000001";

async function fixture({ signer = approver } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const mandate = buildMandate({
    agent: other.address,
    asset: RLUSD,
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
  });
  const mandateSignature = await signer.signTypedData({
    domain: mandate.domain,
    types: mandate.types,
    primaryType: mandate.primaryType,
    message: mandate.message,
  });
  const event = {
    outcome: "paid",
    url: "http://127.0.0.1:4411/resource",
    amount: rlusd("0.01"),
    cumulativeAmount: rlusd("0.22"),
    txHash: `0x${"cd".repeat(32)}`,
    verdict: {
      decision: "ALLOW",
      code: "WITHIN_MANDATE",
      message: "within the signed envelope",
      detail: { remainingTotal: rlusd("1.78") },
    },
  };
  return { mandate, mandateSignature, event, now };
}

test("with a receipt read from chain, every link verifies", async () => {
  const { mandate, mandateSignature, event } = await fixture();
  const chain = await buildReceiptChain({
    event,
    mandate,
    mandateSignature,
    approver: approver.address,
    onChain: {
      receipt: { blockNumber: 9228573, status: 1, to: "0xcAB42800A5ECF0D253Fa2581Bb3334B4DAEfaE91" },
      channelRedeemed: rlusd("0.22"),
    },
  });
  assert.equal(chain.verified, true);
  assert.deepEqual(chain.unverified, []);
  assert.equal(chain.mandateId, hashMandate(mandate));
  assert.equal(chain.links.length, 5);
});

test("without a receipt, settlement is marked unverified and says why", async () => {
  const { mandate, mandateSignature, event } = await fixture();
  const chain = await buildReceiptChain({
    event,
    mandate,
    mandateSignature,
    approver: approver.address,
  });
  assert.equal(chain.verified, false);
  assert.deepEqual(chain.unverified, ["settlement"]);
  const settlement = chain.links.at(-1);
  assert.match(settlement.detail, /the merchant's claim, not proof/);
  assert.match(renderChainText(chain), /UNVERIFIED LINKS: settlement/);
});

test("a reverted transaction does not count as verified", async () => {
  const { mandate, mandateSignature, event } = await fixture();
  const chain = await buildReceiptChain({
    event,
    mandate,
    mandateSignature,
    approver: approver.address,
    onChain: { receipt: { blockNumber: 1, status: 0 } },
  });
  assert.equal(chain.verified, false);
  assert.match(chain.links.at(-1).detail, /REVERTED/);
});

test("a mandate signed by someone else fails the human link", async () => {
  const { mandate, mandateSignature, event } = await fixture({ signer: other });
  const chain = await buildReceiptChain({
    event,
    mandate,
    mandateSignature,
    approver: approver.address, // not who signed
    onChain: { receipt: { blockNumber: 1, status: 1 } },
  });
  assert.equal(chain.links[0].verified, false);
  assert.equal(chain.links[0].fields.recovered.toLowerCase(), other.address.toLowerCase());
  assert.equal(chain.verified, false);
});

test("a granted payment shows the grant as its own link", async () => {
  const { mandate, mandateSignature, event, now } = await fixture();
  const grant = buildGrant({
    mandateId: hashMandate(mandate),
    agent: other.address,
    merchant: MERCHANT,
    asset: RLUSD,
    amount: rlusd("0.2"),
    resource: event.url,
    validUntil: now + 300,
    nonce: now,
    registry: REGISTRY,
  });
  const chain = await buildReceiptChain({
    event: { ...event, amount: rlusd("0.2"), verdict: { ...event.verdict, code: "WITHIN_GRANT" } },
    mandate,
    mandateSignature,
    approver: approver.address,
    grant,
    onChain: { receipt: { blockNumber: 1, status: 1 } },
  });
  const link = chain.links.find((l) => l.step === "grant");
  assert.ok(link, "the grant is a link in the chain, not a footnote");
  assert.equal(link.verified, true);
  assert.equal(link.fields.singleUse, true);
  assert.equal(chain.verified, true);
});

test("a grant link is unverified when the verdict did not rely on it", async () => {
  const { mandate, mandateSignature, event, now } = await fixture();
  const grant = buildGrant({
    mandateId: hashMandate(mandate),
    agent: other.address,
    merchant: MERCHANT,
    asset: RLUSD,
    amount: rlusd("0.2"),
    resource: event.url,
    validUntil: now + 300,
    nonce: now,
    registry: REGISTRY,
  });
  const chain = await buildReceiptChain({
    event, // verdict is WITHIN_MANDATE
    mandate,
    mandateSignature,
    approver: approver.address,
    grant,
    onChain: { receipt: { blockNumber: 1, status: 1 } },
  });
  assert.equal(chain.links.find((l) => l.step === "grant").verified, false);
});

test("the HTML view escapes content and links the explorer", async () => {
  const { mandate, mandateSignature, event } = await fixture();
  const chain = await buildReceiptChain({
    event: { ...event, url: `<img src=x onerror="alert(1)">` },
    mandate,
    mandateSignature,
    approver: approver.address,
    onChain: { receipt: { blockNumber: 7, status: 1 } },
  });
  const html = renderReceiptsHtml([{ title: `a <script>bad</script> title`, chain }], {
    chain: "1449000",
  });

  assert.ok(!html.includes("<script>"), "no injected script survives");
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes(`explorer.testnet.xrplevm.org/tx/${event.txHash}`));
  assert.ok(html.includes("<!doctype html>"));
  // Dark/light both defined, and a background on body, so it is readable
  // wherever a judge opens it.
  assert.ok(html.includes("prefers-color-scheme: light"));
  assert.ok(html.includes("background: var(--bg)"));
});
