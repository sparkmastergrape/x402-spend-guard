import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { createHttpServer } from "./http.js";
import { createMcpServer } from "./mcp.js";
import { fixture, signedMandate, signGrant, approver, AGENT_KEY } from "./test-support.mjs";
import { rlusd } from "spend-gate";

const TOKEN = "test-token-0123456789abcdef";
const BIN = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "guard-server.mjs");

async function httpFixture(opts) {
  const f = await fixture(opts);
  const server = createHttpServer(f.service, { token: TOKEN });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (path, { method = "GET", body, token = TOKEN, type = "application/json" } = {}) =>
    fetch(base + path, {
      method,
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": type } : {}) },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
  const close = async () => {
    await new Promise((r) => server.close(r));
    await f.merchant.close();
  };
  return { ...f, call, close };
}

test("http: every /v1 route needs the bearer token; /healthz does not", async (t) => {
  const h = await httpFixture();
  t.after(h.close);

  assert.equal((await h.call("/healthz", { token: null })).status, 200);
  assert.equal((await h.call("/v1/status", { token: null })).status, 401);
  assert.equal((await h.call("/v1/status", { token: "wrong-token-0123456789" })).status, 401);
  assert.equal((await h.call("/v1/pay", { method: "POST", body: { url: h.url }, token: null })).status, 401);
  assert.equal(h.merchant.stats().challengesIssued, 0, "an unauthenticated call reaches nothing");
  assert.equal((await h.call("/v1/status")).status, 200);
});

test("http: pay, check, status and audit", async (t) => {
  const h = await httpFixture();
  t.after(h.close);

  const check = await (await h.call("/v1/check", { method: "POST", body: { url: h.url } })).json();
  assert.equal(check.verdict.decision, "ALLOW");

  const res = await h.call("/v1/pay", { method: "POST", body: { url: h.url } });
  assert.equal(res.status, 200);
  const paid = await res.json();
  assert.equal(paid.outcome, "paid");

  const status = await (await h.call("/v1/status")).json();
  assert.equal(status.spend.total, paid.amount);
  const audit = await (await h.call("/v1/audit?limit=5")).json();
  assert.equal(audit.length, 1);
});

test("http: the escalation round trip works over the wire", async (t) => {
  const h = await httpFixture();
  t.after(h.close);
  h.merchant.setFault("amount", rlusd("0.2"));

  const stopped = await (await h.call("/v1/pay", { method: "POST", body: { url: h.url } })).json();
  assert.equal(stopped.outcome, "requires_confirmation");
  const grantSignature = await signGrant(stopped.grantToSign);
  const paid = await (
    await h.call("/v1/pay", { method: "POST", body: { url: h.url, grant: stopped.grantToSign, grantSignature } })
  ).json();
  assert.equal(paid.outcome, "paid", paid.message ?? "");
});

test("http: bad input gets a 4xx with a reason", async (t) => {
  const h = await httpFixture();
  t.after(h.close);

  assert.equal((await h.call("/v1/pay", { method: "POST", body: "{nope" })).status, 400);
  assert.equal((await h.call("/v1/pay", { method: "POST", body: { url: h.url }, type: "text/plain" })).status, 415);
  const bad = await h.call("/v1/pay", { method: "POST", body: { url: "file:///etc/passwd" } });
  assert.equal(bad.status, 400);
  assert.match((await bad.json()).error, /http and https/);
  assert.equal((await h.call("/v1/nope")).status, 404);
  const big = await h.call("/v1/pay", { method: "POST", body: JSON.stringify({ url: h.url, pad: "x".repeat(1_100_000) }) });
  assert.equal(big.status, 413);
});

test("http: a server without a real token refuses to start", async () => {
  const { service, merchant } = await fixture();
  await merchant.close();
  assert.throws(() => createHttpServer(service, {}), /token/);
  assert.throws(() => createHttpServer(service, { token: "short" }), /token/);
});

async function mcpClient(service) {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createMcpServer(service).connect(serverSide);
  const client = new Client({ name: "test", version: "0" });
  await client.connect(clientSide);
  return client;
}

const parse = (r) => JSON.parse(r.content[0].text);

test("mcp: lists the four tools", async (t) => {
  const { service, merchant } = await fixture();
  t.after(() => merchant.close());
  const client = await mcpClient(service);
  t.after(() => client.close());

  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((x) => x.name).sort(), ["check_payment", "guarded_fetch", "spend_audit", "spend_status"]);
});

test("mcp: guarded_fetch pays; a refusal is a result, not a tool error", async (t) => {
  const { service, merchant, url } = await fixture({ policy: { expectedPrice: rlusd("0.01") } });
  t.after(() => merchant.close());
  const client = await mcpClient(service);
  t.after(() => client.close());

  const ok = await client.callTool({ name: "guarded_fetch", arguments: { url } });
  assert.equal(ok.isError, undefined);
  assert.equal(parse(ok).outcome, "paid");

  merchant.setFault("amount", rlusd("0.012"));
  const refused = await client.callTool({ name: "guarded_fetch", arguments: { url } });
  assert.notEqual(refused.isError, true, "a refusal must not invite a retry");
  assert.equal(parse(refused).outcome, "refused");
  assert.equal(parse(refused).code, "PRICE_CHANGED");

  const status = parse(await client.callTool({ name: "spend_status", arguments: {} }));
  assert.equal(status.spend.total, rlusd("0.01").toString());
  const audit = parse(await client.callTool({ name: "spend_audit", arguments: { limit: 10 } }));
  assert.equal(audit.length, 2);
});

test("mcp: bad input is a tool error", async (t) => {
  const { service, merchant } = await fixture();
  t.after(() => merchant.close());
  const client = await mcpClient(service);
  t.after(() => client.close());

  const r = await client.callTool({ name: "guarded_fetch", arguments: { url: "file:///etc/passwd" } });
  assert.equal(r.isError, true);
});

test("cli: `guard-server mcp` starts over stdio and pays through the Guard", async (t) => {
  const { merchant, url } = await fixture();
  t.after(() => merchant.close());
  const { json } = await signedMandate();
  const dir = mkdtempSync(join(tmpdir(), "guard-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "mandate.json");
  writeFileSync(file, JSON.stringify(json));

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN, "mcp"],
    env: {
      ...process.env,
      GUARD_MANDATE_FILE: file,
      GUARD_APPROVER: approver.address,
      AGENT_PRIVATE_KEY: AGENT_KEY,
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "cli-test", version: "0" });
  await client.connect(transport);
  t.after(() => client.close());

  const { tools } = await client.listTools();
  assert.equal(tools.length, 4);
  const r = parse(await client.callTool({ name: "guarded_fetch", arguments: { url } }));
  assert.equal(r.outcome, "paid", r.message ?? "");
  assert.equal(merchant.stats().redemptions.length, 1);
});
