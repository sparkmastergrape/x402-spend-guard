# x402-spend-guard for Hermes

This plugin connects Hermes to [guard-server](https://github.com/sparkmastergrape/x402-spend-guard).
A person signs one spend mandate. The guard then decides each x402 payment.

## What it does

| Part | Action |
|---|---|
| `guarded_fetch` | Fetches a URL. The guard pays only if the mandate allows it. |
| `check_payment` | Shows the verdict for a URL. It reserves, signs and records nothing. |
| `spend_status` | Shows the mandate, the caps and the spend. |
| `spend_audit` | Lists recent payer events. |
| `pre_tool_call` hook | Checks other tools whose names look like payment tools. |

The hook takes one of these actions for another payment tool:

| Guard result | Hook action |
|---|---|
| `ALLOW`, or a free URL | Lets the call continue |
| `ESCALATE` | Sends the call to the Hermes approval gate |
| `DENY` | Blocks the call |
| Any other result | Blocks the call |
| Guard not reachable, a crash, or no URL | Blocks the call |

## Setup

1. Install Node.js 22.13 or later.
2. Clone `x402-spend-guard` and run `npm install`.
3. Start `guard-server http` with a signed mandate. Keep it on `127.0.0.1`.
4. Install this plugin in Hermes.
5. Set `GUARD_HTTP_TOKEN` to the guard-server token.

## Disclosure

- **Long-running process:** you run guard-server beside Hermes. The plugin does not start it.
- **Network calls:** the plugin calls guard-server. The default address is `http://127.0.0.1:8402`.
- **Other network calls:** guard-server sends requests to each URL. `check_payment` and the hook also send a request to the URL.
- **Repeat requests:** a checked call can reach the URL again when the tool runs. Check that the URL is safe to request two times.
- **Credentials:** the plugin stores no secret. guard-server holds the agent key. Keep the wallet balance small.
- **Name match:** the hook finds payment tools by name and by these argument names: `url`, `uri`, `endpoint`, `resource`. A tool with another name is not checked.
- **Check limit:** the hook check reserves nothing, and a tool with its own wallet does not use the guard's spend ledger.
- **Approval bypass:** `--yolo` and `approvals.mode: off` skip the Hermes approval gate. An `ESCALATE` result then lets another payment tool run. A `DENY` result still blocks.
- **Spend totals:** guard-server keeps totals in memory. A restart resets them.
- **Testnet only:** use this on a testnet.

## Test

```bash
python -m unittest tests/test_plugin.py
```

## License

Apache-2.0.
