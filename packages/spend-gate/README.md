# spend-gate

A spend policy for agents that pay over HTTP 402. A person signs one EIP-712
Mandate. The Mandate sets the merchant, the per-call cap, the window cap, the
total budget, the purpose and the expiry.

The Guard is a pure function. It has no keys, no network access and no model. It
returns one of three decisions for each quote:

| Decision | Meaning |
|---|---|
| `ALLOW` | The quote is inside the Mandate. |
| `ESCALATE` | A person must approve this payment with a signed Grant. |
| `DENY` | The payment stops. No approval can make it safe. |

## Try it

These commands need no device, no chain and no funds. Run them in this folder.

```bash
node examples/basic.mjs
npm run injection
npm test
```

`examples/basic.mjs` uses a throwaway key and prints an `agent-audit/1` file.
`npm run injection` runs prompt-injection scenes against the Guard.

## Entry points

| Import | Contents |
|---|---|
| `spend-gate` | Mandates, the Guard, `SpendLedger`, revocation, receipts, audit events, network constants |
| `spend-gate/payer` | The x402 payer behind the Guard |
| `spend-gate/audit` | `agent-audit/1` events |
| `spend-gate/ap2` | AP2 mandate mapping |
| `spend-gate/device` | Ledger approver. It needs the optional peer packages. |

`contracts/MandateRegistry.sol` is the on-chain revocation registry.

## Limits

- Use it on a testnet only.
- No physical Ledger device was used.
- `SpendLedger` is in memory and has one writer. A restart resets the totals.
- The agent key lives in the payer process. If that process is compromised, the
  wallet balance is the real loss limit. Keep the balance small.
- Revocation is off unless you configure an RPC URL.

## License

Apache-2.0.
