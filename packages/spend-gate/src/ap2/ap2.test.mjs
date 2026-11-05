import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";

import {
  splitChain,
  parseToken,
  verifyJws,
  resolveDisclosures,
  hashAscii,
  verifyChain,
  issueRoot,
  appendHop,
  generateEs256Jwk,
  signJws,
} from "./sdjwt.js";
import {
  verifyOpenPaymentMandate,
  toGuardMandate,
  signClosedPaymentMandate,
  transactionIdForChallenge,
  x402Instrument,
  VCT_OPEN_PAYMENT,
} from "./index.js";
import { rlusd } from "../mandate/index.js";
import { SpendLedger } from "../ledger-spend/index.js";
import { createMockMerchant } from "../payer/mock-merchant.mjs";
import { createPayer, PAID, REQUIRES_CONFIRMATION } from "../payer/index.js";
import { CHAIN_ID } from "../config/network.js";

const AGENT_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const agentEvm = privateKeyToAccount(AGENT_KEY);
const MERCHANT = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const REGISTRY = "0x0000000000000000000000000000000000000001";
const CENT = 10n ** 16n; // 1 USD cent in RLUSD base units (18 decimals)

// The chained example ("Open Payment Mandate chained with a closed Payment
// Mandate") from docs/ap2/payment_mandate.md in google-agentic-commerce/AP2,
// fetched from main on 2026-11-02. Apache-2.0. Its root issuer key is not
// published, so only the key-bound hop can be checked cryptographically.
const SPEC_CHAIN = readFileSync(new URL("./vectors/spec-open-closed-chain.txt", import.meta.url), "utf8").trim();

test("spec vector: the agent's hop verifies under cnf.jwk, and sd_hash matches", async () => {
  const [root, hop] = splitChain(SPEC_CHAIN).map(parseToken);
  const open = resolveDisclosures(root.payload, root).delegate_payload[0];
  assert.equal(open.vct, VCT_OPEN_PAYMENT);
  assert.equal(open.constraints[1].allowed[0].id, "merchant_1", "a nested disclosure resolves");

  await verifyJws(hop.issuerJwt, open.cnf.jwk);
  assert.equal(hop.payload.sd_hash, hashAscii(root.sdJwt, root.sdAlg));

  const closed = resolveDisclosures(hop.payload, hop).delegate_payload[0];
  assert.equal(closed.vct, "mandate.payment.1");
  assert.deepEqual(closed.payment_amount, { amount: 19900, currency: "USD" });
});

test("spec vector: without the issuer's key the chain does not verify", async () => {
  const { publicJwk } = await generateEs256Jwk();
  await assert.rejects(verifyChain(SPEC_CHAIN, publicJwk, { now: 1777342400 }), /signature/);
});

async function keys() {
  return { user: await generateEs256Jwk(), agent: await generateEs256Jwk() };
}

function openMandate(agentPublicJwk, over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    vct: VCT_OPEN_PAYMENT,
    constraints: [
      { type: "payment.amount_range", currency: "USD", max: 5, min: 0 },
      { type: "payment.budget", currency: "USD", max: 200 },
      { type: "payment.agent_recurrence", frequency: "ON_DEMAND" },
      { type: "payment.allowed_payees", allowed: [{ id: `eip155:${CHAIN_ID}:${MERCHANT}`, name: "Data Co" }] },
      ...(over.constraints ?? []),
    ],
    cnf: { jwk: agentPublicJwk },
    iat: now - 10,
    exp: now + 3600,
    ...over.fields,
  };
}

test("round trip: the user issues, the agent closes, the chain verifies", async () => {
  const { user, agent } = await keys();
  const open = await issueRoot(openMandate(agent.publicJwk), user.privateJwk, { kid: "user-1" });
  const chain = await appendHop(open, { vct: "mandate.payment.1", transaction_id: "t", payee: { id: "m", name: "M" } }, agent.privateJwk, {
    aud: "merchant.example",
    nonce: "n-1",
  });

  const { hops } = await verifyChain(chain, user.publicJwk, { aud: "merchant.example", nonce: "n-1" });
  assert.equal(hops.length, 2);
  assert.equal(hops[1].items[0].vct, "mandate.payment.1");

  await assert.rejects(verifyChain(chain, user.publicJwk, { aud: "elsewhere", nonce: "n-1" }), /aud/);
  await assert.rejects(verifyChain(chain, user.publicJwk, { aud: "merchant.example", nonce: "other" }), /nonce/);
  await assert.rejects(verifyChain(chain, agent.publicJwk), /signature/, "the wrong root key");
});

test("tampering anywhere breaks the chain", async () => {
  const { user, agent } = await keys();
  const open = await issueRoot(openMandate(agent.publicJwk), user.privateJwk);
  const chain = await appendHop(open, { vct: "mandate.payment.1" }, agent.privateJwk, { aud: "a", nonce: "n" });

  // Swap the open mandate's disclosure for one with a bigger cap.
  const [root] = splitChain(open).map(parseToken);
  const forged = Buffer.from(JSON.stringify(["salt", { ...openMandate(agent.publicJwk), constraints: [] }])).toString("base64url");
  await assert.rejects(verifyChain(`${root.issuerJwt}~${forged}~`, user.publicJwk), /not referenced|disclosure/);

  // A hop signed by a key that is not the delegate.
  const stranger = await generateEs256Jwk();
  const rogue = await appendHop(open, { vct: "mandate.payment.1" }, stranger.privateJwk, { aud: "a", nonce: "n" });
  await assert.rejects(verifyChain(rogue, user.publicJwk), /signature/);

  // A hop bound to a different open mandate.
  const other = await issueRoot(openMandate(agent.publicJwk), user.privateJwk);
  const hop = splitChain(chain).pop();
  const spliced = `${other.slice(0, -1)}~~${hop}`;
  await assert.rejects(verifyChain(spliced, user.publicJwk), /binding hash/);
});

test("an expired mandate, or a terminal hop that delegates further, is refused", async () => {
  const { user, agent } = await keys();
  const old = await issueRoot(openMandate(agent.publicJwk, { fields: { exp: 1000 } }), user.privateJwk);
  await assert.rejects(verifyChain(old, user.publicJwk), /expired/);

  // A properly signed terminal hop (typ kb+sd-jwt) that still carries cnf.
  const open = await issueRoot(openMandate(agent.publicJwk), user.privateJwk);
  const prev = parseToken(open);
  const disclosure = Buffer.from(JSON.stringify(["s", { vct: "x", cnf: { jwk: agent.publicJwk } }])).toString("base64url");
  const jwt = await signJws(
    { typ: "kb+sd-jwt" },
    {
      delegate_payload: [{ "...": hashAscii(disclosure, "sha-256") }],
      iat: Math.floor(Date.now() / 1000),
      aud: "a",
      nonce: "n",
      sd_hash: hashAscii(prev.sdJwt, prev.sdAlg),
      _sd_alg: "sha-256",
    },
    agent.privateJwk,
  );
  await assert.rejects(verifyChain(`${open.slice(0, -1)}~~${jwt}~${disclosure}~`, user.publicJwk), /must not carry cnf/);
});

test("toGuardMandate: the AP2 constraints become the Guard's caps", async () => {
  const { user, agent } = await keys();
  const notAfter = new Date(Date.now() + 1800_000).toISOString();
  const token = await issueRoot(
    openMandate(agent.publicJwk, {
      constraints: [
        { type: "payment.execution_date", not_after: notAfter },
        { type: "payment.allowed_payment_instruments", allowed: [x402Instrument()] },
      ],
    }),
    user.privateJwk,
  );
  const { open, agentJwk } = await verifyOpenPaymentMandate(token, user.publicJwk);
  assert.deepEqual(agentJwk, agent.publicJwk);

  const r = toGuardMandate(open, { agent: agentEvm.address, registry: REGISTRY });
  assert.equal(r.mandate.message.maxPerCall, 5n * CENT);
  assert.equal(r.mandate.message.maxTotal, 200n * CENT);
  assert.equal(r.mandate.message.merchant, MERCHANT);
  assert.equal(r.mandate.message.agent, agentEvm.address);
  assert.equal(r.mandate.message.validUntil, BigInt(Math.floor(Date.parse(notAfter) / 1000)), "the earlier of exp and not_after");
  assert.equal(r.maxPayments, null, "ON_DEMAND recurrence: reusable");
  assert.equal(r.currency, "USD");
});

test("toGuardMandate refuses what it cannot enforce exactly", async () => {
  const { agent } = await keys();
  const base = (constraints, replace = false) => {
    const m = openMandate(agent.publicJwk);
    m.constraints = replace ? constraints : [...m.constraints, ...constraints];
    return m;
  };
  const cfg = { agent: agentEvm.address, registry: REGISTRY };
  const cases = [
    [base([{ type: "payment.mystery" }]), "AP2_CONSTRAINT_UNSUPPORTED"],
    [base([{ type: "payment.agent_recurrence", frequency: "DAILY" }], true), "AP2_CONSTRAINT_UNSUPPORTED"],
    [
      base([
        { type: "payment.amount_range", currency: "USD", max: 5 },
        { type: "payment.allowed_payees", allowed: [{ id: MERCHANT, name: "a" }, { id: MERCHANT, name: "b" }] },
      ], true),
      "AP2_CONSTRAINT_UNSUPPORTED",
    ],
    [
      base([
        { type: "payment.amount_range", currency: "USD", max: 5 },
        { type: "payment.allowed_payees", allowed: [{ id: "merchant_1", name: "Demo" }] },
      ], true),
      "AP2_CONSTRAINT_UNSUPPORTED",
    ],
    [base([{ type: "payment.allowed_payees", allowed: [{ id: MERCHANT, name: "a" }] }], true), "AP2_CONSTRAINT_UNSUPPORTED"],
    [base([{ type: "payment.reference", conditional_transaction_id: "x" }]), "AP2_REFERENCE_UNVERIFIABLE"],
    [base([{ type: "payment.allowed_pisps", allowed: [] }]), "AP2_CONSTRAINT_UNSUPPORTED"],
    [base([{ type: "payment.allowed_payment_instruments", allowed: [{ id: "card-1", type: "card" }] }]), "AP2_INSTRUMENT_NOT_ALLOWED"],
    [
      base([
        { type: "payment.amount_range", currency: "JPY", max: 5 },
        { type: "payment.allowed_payees", allowed: [{ id: MERCHANT, name: "a" }] },
      ], true),
      "AP2_CURRENCY_UNSUPPORTED",
    ],
    [
      base([
        { type: "payment.amount_range", currency: "USD", max: 5, min: 1 },
        { type: "payment.allowed_payees", allowed: [{ id: MERCHANT, name: "a" }] },
      ], true),
      "AP2_CONSTRAINT_UNSUPPORTED",
    ],
    [
      base([
        { type: "payment.amount_range", currency: "USD", max: 5.5 },
        { type: "payment.allowed_payees", allowed: [{ id: MERCHANT, name: "a" }] },
      ], true),
      "AP2_MALFORMED",
    ],
  ];
  for (const [open, code] of cases) assert.throws(() => toGuardMandate(open, cfg), (e) => e.code === code, code);

  const refOk = toGuardMandate(base([{ type: "payment.reference", conditional_transaction_id: "x" }]), {
    ...cfg,
    allowUnchecked: ["payment.reference"],
  });
  assert.deepEqual(refOk.unchecked, ["payment.reference"], "an opted-in gap is reported, not hidden");
});

test("without agent_recurrence a mandate pays once, capped at amount_range.max", async () => {
  const { agent } = await keys();
  const m = openMandate(agent.publicJwk);
  m.constraints = m.constraints.filter((c) => c.type !== "payment.agent_recurrence");
  const r = toGuardMandate(m, { agent: agentEvm.address, registry: REGISTRY });
  assert.equal(r.maxPayments, 1);
  assert.equal(r.mandate.message.maxTotal, 5n * CENT);
});

test("the closed Payment Mandate records the payment in minor units, chained to the open one", async () => {
  const { user, agent } = await keys();
  const open = await issueRoot(openMandate(agent.publicJwk), user.privateJwk);
  const txid = transactionIdForChallenge("eyJ4NDAyVmVyc2lvbiI6Mn0");
  const { closed, token } = await signClosedPaymentMandate({
    openToken: open,
    agentPrivateJwk: agent.privateJwk,
    payee: { id: MERCHANT, name: "Data Co" },
    amount: 1n * CENT,
    scale: CENT,
    currency: "USD",
    instrument: x402Instrument(),
    transactionId: txid,
    aud: "http://merchant",
    nonce: "n",
  });
  assert.deepEqual(closed.payment_amount, { amount: 1, currency: "USD" });
  const { hops } = await verifyChain(token, user.publicJwk, { aud: "http://merchant", nonce: "n" });
  assert.equal(hops[1].items[0].transaction_id, txid);

  await assert.rejects(
    signClosedPaymentMandate({
      openToken: open, agentPrivateJwk: agent.privateJwk, payee: {}, amount: CENT / 10n, scale: CENT,
      currency: "USD", instrument: x402Instrument(), transactionId: "t", aud: "a", nonce: "n",
    }),
    (e) => e.code === "AP2_AMOUNT_NOT_REPRESENTABLE",
  );
});

test("end to end: an AP2 mandate drives the payer over x402", async (t) => {
  const { user, agent } = await keys();
  const token = await issueRoot(openMandate(agent.publicJwk), user.privateJwk);
  const { open } = await verifyOpenPaymentMandate(token, user.publicJwk);
  const { mandate } = toGuardMandate(open, { agent: agentEvm.address, registry: REGISTRY });

  const merchant = createMockMerchant({ payTo: MERCHANT, agent: agentEvm.address, price: rlusd("0.01") });
  const { url } = await merchant.listen();
  t.after(() => merchant.close());
  const payer = createPayer({ mandate, signatureValid: true, ledger: new SpendLedger(), signer: agentEvm });

  assert.equal((await payer.buy(url)).outcome, PAID, "1 cent is inside a 5 cent cap");
  merchant.setFault("amount", rlusd("0.06"));
  const r = await payer.buy(url);
  assert.equal(r.outcome, REQUIRES_CONFIRMATION, "6 cents is over the user's amount_range.max");
  assert.equal(r.verdict.code, "OVER_PER_CALL");
});
