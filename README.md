# x402-spend-guard

Spend limits for AI agents that pay over x402. A person signs one spend mandate.
The Guard then checks each payment against that mandate before the agent signs.

| Package | Purpose |
|---|---|
| [`packages/spend-gate`](packages/spend-gate) | Mandates, the Guard, the spend ledger, grants, receipts and audit events |
| [`packages/guard-server`](packages/guard-server) | MCP and HTTP interface to the Guard |
| [`hermes-plugin`](hermes-plugin) | Hermes Agent plugin for guard-server |

## Status

- Version 0.1.0. Use it on a testnet only.
- The default network is XRPL EVM Testnet, chain ID 1449000.
- The automatic tests use a local mock merchant and test keys.
- The tests do not use a live merchant or real funds.
- No physical Ledger device was used.
- The spend ledger is in memory. A restart resets the totals.

## Install and test

Node.js 22.13 or later is necessary.

```bash
git clone https://github.com/sparkmastergrape/x402-spend-guard.git
cd x402-spend-guard
npm install
npm test
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
