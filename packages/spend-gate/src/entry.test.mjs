// The entry point exports what the README documents, loads without a device or
// a network, and nothing in the package reaches outside its own folder.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import * as sg from "../index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("the documented public surface is exported", () => {
  const fns = [
    // mandate
    "buildMandate", "hashMandate", "mandateId", "verifyMandate", "recoverMandateSigner",
    "toSignerPayload", "describeMandate", "assertWellFormed", "buildDomain", "rlusd", "formatRlusd",
    // grants
    "buildGrant", "hashGrant", "verifyGrant", "toGrantSignerPayload", "describeGrant", "grantAmount",
    // guard
    "evaluate", "amountFromAccepts", "isAutonomous", "describeVerdict",
    // ledger, revocation, receipts
    "SpendLedger", "assertSingleWriter", "createRevocationChecker", "createOnChainChecker",
    "buildReceiptChain", "renderChainText", "renderReceiptsHtml",
    // audit
    "makeEvent", "makeRunId", "verdictEvents", "envelope", "validateEnvelope", "invoiceIdFor", "cleanSummary",
  ];
  for (const name of fns) assert.equal(typeof sg[name], "function", name);
  assert.deepEqual([sg.ALLOW, sg.ESCALATE, sg.DENY], ["ALLOW", "ESCALATE", "DENY"]);
  assert.equal(sg.AUDIT_SCHEMA, "agent-audit/1");
  assert.equal(sg.EVM_TESTNET_NETWORK, "eip155:1449000");
  assert.deepEqual(sg.SIGNERS, ["software-key-standin", "ledger-emulator", "ledger-device"]);
  assert.equal(sg.network.CHAIN_ID, 1449000);
  assert.ok(sg.CODES.OVER_PER_CALL);
});

test("what needs a device, the SDK or ethers is not exported from the entry point", () => {
  for (const name of ["createPayer", "connectSpeculosApprover", "createMockMerchant", "runScene"])
    assert.equal(name in sg, false, name);
});

// ---- import graph, read from source ----

const SKIP_DIRS = new Set(["node_modules", ".git"]);
function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(m?js)$/.test(name)) out.push(p);
  }
  return out;
}

// Static `import ... from "x"` and `export ... from "x"`, and side-effect `import "x"`.
const STATIC = /^\s*(?:import|export)\s+(?:[\w*\s{},$]+?\s+from\s+)?['"]([^'"]+)['"]/gm;
const specifiersOf = (file) => [...readFileSync(file, "utf8").matchAll(STATIC)].map((m) => m[1]);

test("importing index.js pulls in viem only: no SDK, ethers, ledgerhq or node:fs/http", () => {
  const seen = new Set();
  const bare = new Set();
  const queue = [join(ROOT, "index.js")];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    for (const spec of specifiersOf(file)) {
      if (spec.startsWith(".")) queue.push(resolve(dirname(file), spec));
      else bare.add(spec);
    }
  }
  assert.deepEqual([...bare].sort(), ["viem"]);
  assert.ok(seen.size > 8, `walked ${seen.size} files`);
});

test("every relative import in the package resolves to a file inside the package", () => {
  for (const file of walk(ROOT)) {
    for (const spec of specifiersOf(file).filter((s) => s.startsWith("."))) {
      const target = resolve(dirname(file), spec);
      const rel = relative(ROOT, target);
      assert.ok(!rel.startsWith("..") && !rel.split(sep).includes(".."), `${relative(ROOT, file)} imports ${spec}, outside the package`);
      assert.ok(existsSync(target), `${relative(ROOT, file)} imports ${spec}, which does not exist`);
    }
  }
});
