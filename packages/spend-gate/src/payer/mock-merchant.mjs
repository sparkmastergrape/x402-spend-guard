// A local x402 merchant that speaks the open x402 v2 `exact` scheme but settles nothing.
//
// It uses the genuine `@x402/core` encoders, so the bytes on the wire are the bytes
// a real x402 server produces, and it verifies the agent's EIP-3009 authorization
// the way the token contract would (signer, payee, value, time window, nonce). What
// it does NOT do is touch a chain: no gas, no RLUSD. That lets the whole payer path —
// 402 → Guard verdict → reserve → sign → retry → commit — be exercised and
// regression-tested without funds.
//
// It can also misbehave on purpose, which is how we test that the Guard holds:
//   payTo            — redirect payment to an attacker (prompt-injection)
//   amount           — quote a price above the mandate's per-call cap
//   asset / network / scheme — mismatches that must DENY

import { createServer } from "node:http";
import { keccak256, toHex, verifyTypedData } from "viem";
import {
  encodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import { RLUSD, X402_NETWORK, X402_SCHEME, HEADERS, CHAIN_ID, X402_VERSION } from "../config/network.js";

/** EIP-712 domain the mock states for its token. Real merchants state the real one. */
export const MOCK_TOKEN_DOMAIN = { name: "RLUSD", version: "1" };

const TRANSFER_WITH_AUTHORIZATION = [
  { name: "from", type: "address" },
  { name: "to", type: "address" },
  { name: "value", type: "uint256" },
  { name: "validAfter", type: "uint256" },
  { name: "validBefore", type: "uint256" },
  { name: "nonce", type: "bytes32" },
];

/**
 * @param {object} opts
 * @param {string} opts.payTo        merchant payout address
 * @param {string} opts.agent        address whose authorization signature we accept
 * @param {bigint} opts.price        per-call price in RLUSD base units
 * @param {object} [opts.faults]     deliberate misbehaviour, see above
 */
export function createMockMerchant({ payTo, agent, price, faults = {} } = {}) {
  const redemptions = [];
  const usedNonces = new Set();
  let settledTotal = 0n;
  let challengesIssued = 0;

  const resourceUrlFor = (host) => `http://${host}/resource`;

  function buildChallenge(host) {
    challengesIssued++;
    return {
      x402Version: X402_VERSION,
      error: "payment required",
      resource: { url: resourceUrlFor(host), description: "mock market data", mimeType: "application/json" },
      accepts: [
        {
          scheme: faults.scheme ?? X402_SCHEME,
          network: faults.network ?? X402_NETWORK,
          amount: String(faults.amount ?? price),
          asset: faults.asset ?? RLUSD,
          payTo: faults.payTo ?? payTo,
          maxTimeoutSeconds: 150,
          extra: { ...MOCK_TOKEN_DOMAIN },
        },
      ],
    };
  }

  /** Verify the agent's EIP-3009 authorization the way the token contract would. */
  async function verifyAuthorization(payload) {
    const auth = payload?.payload?.authorization;
    const sig = payload?.payload?.signature;
    if (!auth || !sig) return { ok: false, reason: "missing authorization or signature" };

    const expectedTo = (faults.payTo ?? payTo).toLowerCase();
    if (String(auth.to).toLowerCase() !== expectedTo)
      return { ok: false, reason: `authorization pays ${auth.to}, not ${expectedTo}` };
    const value = BigInt(auth.value);
    const quoted = BigInt(faults.amount ?? price);
    if (value !== quoted) return { ok: false, reason: `authorization value ${value} != price ${quoted}` };
    const nowS = BigInt(Math.floor(Date.now() / 1000));
    if (nowS < BigInt(auth.validAfter) || nowS >= BigInt(auth.validBefore))
      return { ok: false, reason: "authorization is outside its time window" };
    if (usedNonces.has(String(auth.nonce).toLowerCase()))
      return { ok: false, reason: "authorization nonce already used" };

    let valid;
    try {
      valid = await verifyTypedData({
        address: auth.from,
        domain: { ...MOCK_TOKEN_DOMAIN, chainId: CHAIN_ID, verifyingContract: faults.asset ?? RLUSD },
        types: { TransferWithAuthorization: TRANSFER_WITH_AUTHORIZATION },
        primaryType: "TransferWithAuthorization",
        message: { ...auth, value, validAfter: BigInt(auth.validAfter), validBefore: BigInt(auth.validBefore) },
        signature: sig,
      });
    } catch (e) {
      return { ok: false, reason: `unverifiable signature: ${e.message}` };
    }
    if (!valid) return { ok: false, reason: "signature does not match the authorization" };
    if (String(auth.from).toLowerCase() !== agent.toLowerCase())
      return { ok: false, reason: `authorization from ${auth.from}, expected ${agent}` };
    return { ok: true, payer: auth.from, value, nonce: String(auth.nonce).toLowerCase() };
  }

  // Every handler path is wrapped: an async throw inside a node:http handler
  // never reaches the client, so the request would hang forever and a test
  // would time out with no diagnosis. A merchant that 500s is debuggable.
  const server = createServer((req, res) => {
    handle(req, res).catch((e) => {
      if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(`mock merchant error: ${e.stack}`);
    });
  });

  async function handle(req, res) {
    const host = req.headers.host;
    const url = new URL(req.url, `http://${host}`);
    if (url.pathname !== "/resource") {
      res.writeHead(404).end("not found");
      return;
    }

    const signatureHeader = req.headers[HEADERS.signature.toLowerCase()];
    if (!signatureHeader) {
      res.writeHead(402, {
        "Content-Type": "application/json",
        [HEADERS.required]: encodePaymentRequiredHeader(buildChallenge(host)),
        Vary: HEADERS.signature,
      });
      res.end(JSON.stringify({ error: "payment required" }));
      return;
    }

    let payload;
    try {
      payload = decodePaymentSignatureHeader(String(signatureHeader));
    } catch (e) {
      res.writeHead(400).end(JSON.stringify({ error: `bad payment payload: ${e.message}` }));
      return;
    }

    const check = await verifyAuthorization(payload);
    if (!check.ok) {
      res.writeHead(402).end(JSON.stringify({ error: check.reason }));
      return;
    }

    // Settlement would happen on-chain here. We only record it.
    usedNonces.add(check.nonce);
    settledTotal += check.value;
    const txHash = keccak256(toHex(`mock-settle-${redemptions.length}-${check.nonce}`));
    redemptions.push({ amount: check.value, txHash, payer: check.payer });

    res.writeHead(200, {
      "Content-Type": "application/json",
      [HEADERS.response]: encodePaymentResponseHeader({
        success: true,
        network: faults.network ?? X402_NETWORK,
        transaction: txHash,
        payer: check.payer,
      }),
    });
    res.end(JSON.stringify({ data: { price: "mock", ts: Date.now() }, seq: redemptions.length }));
  }

  return {
    server,
    listen: () =>
      new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => {
          const { port } = server.address();
          resolve({ port, url: `http://127.0.0.1:${port}/resource` });
        });
      }),
    close: () => new Promise((resolve) => server.close(resolve)),
    stats: () => ({
      redemptions: [...redemptions],
      challengesIssued,
      settledTotal,
    }),
    setFault: (k, v) => {
      faults[k] = v;
    },
    clearFaults: () => {
      for (const k of Object.keys(faults)) delete faults[k];
    },
  };
}
