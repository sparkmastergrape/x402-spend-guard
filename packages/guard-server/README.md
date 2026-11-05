# guard-server

MCP and HTTP interface to `spend-gate`. The agent asks for a URL. The server
fetches it and pays over x402 only if the Guard allows the payment under a
signed spend mandate.

## Run

```bash
GUARD_MANDATE_FILE=mandate.json \
GUARD_APPROVER=0xApproverAddress \
AGENT_PRIVATE_KEY=0x... \
GUARD_RPC_URL=https://rpc.testnet.xrplevm.org \
npx guard-server mcp
```

For HTTP, set `GUARD_HTTP_TOKEN` (16 or more characters) and run
`guard-server http --port 8402`. The server listens on 127.0.0.1 by default.

`mandate.json` holds `{"mandate": {...}, "signature": "0x..."}`. Write every
uint as a decimal string. `src/config.js` lists all variables.

## AP2 mandates

The server can also take its spend limits from an AP2 v0.2 open Payment
Mandate that the user signed. Set `GUARD_AP2_MANDATE_FILE` and
`GUARD_AP2_USER_JWK` instead of `GUARD_MANDATE_FILE`.

| AP2 constraint                        | Guard rule                                   |
| ------------------------------------- | -------------------------------------------- |
| `payment.amount_range.max`            | per-call cap                                 |
| `payment.budget.max`                  | total cap                                    |
| `payment.allowed_payees`              | the one payee (EVM address or CAIP-10 id)    |
| `payment.execution_date`, `iat`/`exp` | valid-from and valid-until                   |
| `payment.agent_recurrence`            | `ON_DEMAND` only. Without it, one payment    |
| `payment.allowed_payment_instruments` | must list `x402.exact` for this asset        |

The server refuses to start on a constraint it cannot enforce exactly. Examples
are a second payee, a `DAILY` frequency, a minimum amount, or an unknown type.
`payment.reference` points to an AP2 checkout, and an x402 purchase has none.
It starts only if you set `GUARD_AP2_ALLOW_UNCHECKED=payment.reference`, and
the server then warns that it does not check it.

With `GUARD_AP2_AGENT_JWK_FILE` (the private half of the mandate's `cnf.jwk`),
each paid result carries `ap2PaymentMandate`: a closed Payment Mandate chained
to the user's open one. Its `transaction_id` is the SHA-256 of the merchant's
`PAYMENT-REQUIRED` header. That binding is ours. AP2 defines `transaction_id`
for a checkout JWT.

AP2 mode has no revocation check. Keep the mandate's `exp` short.

## Tools and routes

| MCP tool        | HTTP route        | What it does                                                      |
| --------------- | ----------------- | ----------------------------------------------------------------- |
| `guarded_fetch` | `POST /v1/pay`    | Fetch, and pay if the Guard allows                                 |
| `check_payment` | `POST /v1/check`  | Show the verdict a payment would get. Reserves, signs, records nothing |
| `spend_status`  | `GET /v1/status`  | Show the mandate, its caps and the spend so far                    |
| `spend_audit`   | `GET /v1/audit`   | List recent payer events                                           |

## Outcomes

- `paid`: the payment settled. `body` holds the resource.
- `refused`: stop. Do not retry, and do not look for another way to pay.
- `requires_confirmation`: a human must sign `grantToSign` on the approval
  device. Then call again with `grant` and `grantSignature`. A Grant pays once.

A refusal is a normal result, not an error. Only bad input and an unreachable
resource return an error.

## Limits

- The agent key lives in this process. The token balance of the agent wallet
  is the real loss limit if the host is compromised. Keep that balance small.
- Without `GUARD_RPC_URL`, revocation is OFF, and the server prints a warning.
- The spend ledger is in memory. A restart resets the spend totals.
