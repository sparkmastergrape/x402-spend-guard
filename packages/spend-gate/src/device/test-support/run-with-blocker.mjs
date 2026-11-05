// Test support for the device tests. Not part of the package's public surface
// (nothing exports it, and it is not packed).
//
// Run node in a child process whose module loaders cannot resolve the device
// packages (block-device-packages.mjs), with a clean environment: none of the
// switches the device tests read leak in from the parent, and `env` sets the ones
// a test wants (a value of undefined deletes the variable). Asynchronous, so a
// test that runs several children at once does not block its own fake servers.

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The package root (spend-gate/). */
export const ROOT = join(HERE, "..", "..", "..");

const BLOCKER = pathToFileURL(join(HERE, "block-device-packages.mjs")).href;
const SWITCHES = ["NODE_TEST_CONTEXT", "SPEND_GATE_REQUIRE_DEVICE", "BLOCK_DEVICE_PACKAGES_ONLY", "BLOCK_DEVICE_PACKAGES_THROW", "SPECULOS_URL"];

/** node --import <blocker> <nodeArgs...>, cwd = package root. Resolves to { status, signal, stdout, stderr }. */
export function spawnBlocked(nodeArgs, env = {}) {
  const childEnv = { ...process.env };
  for (const name of SWITCHES) delete childEnv[name];
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) delete childEnv[name];
    else childEnv[name] = value;
  }
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", BLOCKER, ...nodeArgs], { cwd: ROOT, env: childEnv });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill(), 90_000);
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", (error) => (clearTimeout(timer), reject(error)));
    child.on("close", (status, signal) => (clearTimeout(timer), resolve({ status, signal, stdout, stderr })));
  });
}

/** Run ES module source `code` under the blocker; it prints one line `RESULT:<json>`, which is parsed and returned. */
export async function runProbe(code, env = {}) {
  const r = await spawnBlocked(["--input-type=module", "-e", code], env);
  const line = r.stdout.split(/\r?\n/).find((l) => l.startsWith("RESULT:"));
  if (!line) throw new Error(`probe produced no result (exit ${r.status}, signal ${r.signal})\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
  return JSON.parse(line.slice("RESULT:".length));
}

/** Probe: import src/device/index.mjs and report what happened. */
export const WRAPPER_PROBE = `
import { pathToFileURL } from "node:url";
import { join } from "node:path";
let out;
try {
  const m = await import(pathToFileURL(join(process.cwd(), "src/device/index.mjs")).href);
  out = { loaded: Object.keys(m).sort() };
} catch (e) {
  out = { threw: true, name: e?.constructor?.name, code: e?.code, message: e?.message, missing: e?.missing,
          hasCause: e?.cause !== undefined, causeCode: e?.cause?.code, causeMessage: e?.cause?.message };
}
console.log("RESULT:" + JSON.stringify(out));
`;
