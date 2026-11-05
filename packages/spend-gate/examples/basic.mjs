// Offline: no device, no chain, no funds. stdout is the agent-audit/1 envelope, stderr is a table.
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { buildMandate, hashMandate, verifyMandate, rlusd, SpendLedger, evaluate, ALLOW, verdictEvents, envelope, makeRunId, network } from "../index.js";

const approver = privateKeyToAccount(generatePrivateKey()); // stands in for the Ledger; a throwaway key
const agent = privateKeyToAccount(generatePrivateKey()).address;
const merchant = "0xFf9395aa0918A789B4dC40e7cf147A73c92fcbf8";
const now = Math.floor(Date.now() / 1000);
const mandate = buildMandate({ agent, merchant, maxPerCall: rlusd("0.05"), maxPerWindow: rlusd("0.5"), maxTotal: rlusd("2"),
  purpose: "market-data", validFrom: now - 60, validUntil: now + 3600, registry: network.MANDATE_REGISTRY });
const signature = await approver.signTypedData(mandate); // the one human step; on a Ledger this is the device
const signatureValid = (await verifyMandate(mandate, signature, approver.address)).ok;
const id = hashMandate(mandate), ledger = new SpendLedger(), events = [];
const quote = (amount, asset = network.RLUSD) => ({ resource: { url: "https://merchant.example/data" },
  accepts: [{ scheme: network.X402_SCHEME, network: network.X402_NETWORK, amount: String(amount), asset, payTo: merchant, extra: { ledger: network.PAYMENT_LEDGER } }] });
for (const challenge of [quote(rlusd("0.01")), quote(rlusd("0.4")), quote(rlusd("0.01"), "0x000000000000000000000000000000000000bEEF")]) {
  const spend = ledger.snapshot(id, { windowSeconds: 3600 });
  const verdict = evaluate({ mandate, mandateId: id, signatureValid, challenge, agent, now, spend, policy: { expectedLedger: network.PAYMENT_LEDGER } });
  if (verdict.decision === ALLOW) ledger.commit(ledger.reserve({ mandateId: id, amount: BigInt(challenge.accepts[0].amount), caps: mandate.message }).reservationId);
  events.push(...verdictEvents({ challenge, verdict, mandateId: id, intent: "fetch today's price data", ts: now, mandate }));
}
const doc = envelope({ run_id: makeRunId("basic-example", now), events }); // throws if it breaks agent-audit/1
for (const e of doc.events) console.error(`${e.stage.padEnd(13)} ${e.actor.padEnd(11)} ${e.outcome.padEnd(8)} ${e.summary}`);
console.log(JSON.stringify(doc, null, 2));
