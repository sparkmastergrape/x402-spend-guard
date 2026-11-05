#!/usr/bin/env node
// guard-server mcp                     MCP over stdio
// guard-server http [--port N] [--host H]   HTTP, default 127.0.0.1:8402
//
// Configuration comes from environment variables; see src/config.js.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { serviceFromEnv } from "../src/config.js";
import { createMcpServer } from "../src/mcp.js";
import { createHttpServer } from "../src/http.js";

function flag(args, name, fallback) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

async function main(argv) {
  const [mode, ...rest] = argv;
  if (mode !== "mcp" && mode !== "http") {
    process.stderr.write("usage: guard-server mcp | guard-server http [--port 8402] [--host 127.0.0.1]\n");
    process.exit(2);
  }

  const service = await serviceFromEnv();

  if (mode === "mcp") {
    await createMcpServer(service).connect(new StdioServerTransport());
    process.stderr.write(`guard-server: MCP on stdio, mandate ${service.mandateId}\n`);
    return;
  }

  const port = Number(flag(rest, "port", 8402));
  const host = flag(rest, "host", "127.0.0.1");
  const server = createHttpServer(service, { token: process.env.GUARD_HTTP_TOKEN });
  server.listen(port, host, () =>
    process.stderr.write(`guard-server: HTTP on http://${host}:${port}, mandate ${service.mandateId}\n`),
  );
}

main(process.argv.slice(2)).catch((e) => {
  process.stderr.write(`guard-server: ${e.message}\n`);
  process.exit(1);
});
