// The device packages are optional. This file checks, without any of them
// installed, that:
//   - the manifest declares them as optional peers and nothing else, and that
//     `spend-gate/device` is a wrapper that turns a missing peer into one clear error,
//   - every bare import in src/device/ is one of those peers,
//   - the main entries (index.js, src/payer, src/audit) load with the device
//     packages unable to resolve, even on a machine that has them,
//   - the blocker used for that really blocks (a positive control),
//   - SPEND_GATE_REQUIRE_DEVICE=1 turns the device test's skip into a failure,
//   - `npm pack` ships every file the four entries import, and no stray secret,
//     log, node_modules, test or test-support file.
// The device module itself is exercised in speculos-approver.test.mjs, which
// skips when the packages are absent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { INSTALL_COMMAND, KIT_PEERS, OPTIONAL_PEERS, explainMissingPeer, missingPeerName } from "./missing-peers.mjs";
import { ROOT as PACKAGE_ROOT, WRAPPER_PROBE, runProbe, spawnBlocked } from "./test-support/run-with-blocker.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
assert.equal(resolve(PACKAGE_ROOT), ROOT);
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

const PEERS = {
  "@ledgerhq/device-management-kit": "^1.11.0",
  "@ledgerhq/device-signer-kit-ethereum": "^1.18.2",
  "@ledgerhq/device-transport-kit-speculos": "^1.3.0",
  "reflect-metadata": "^0.2.2",
};

const FILES = [
  "index.js", "src", "contracts", "examples", "README.md", "NOTICE", "LICENSE",
  "!**/.env", "!**/.env.*", "!**/.envrc", "!**/*.pem", "!**/*.key", "!**/id_rsa*", "!**/secrets.*", "!**/*.log",
  "!**/node_modules", "!**/*.test.mjs", "!**/test-support",
];

// ---------------------------------------------------------------- manifest

test("the device packages are optional peers, and not dependencies", () => {
  assert.deepEqual(pkg.peerDependencies, PEERS);
  assert.deepEqual(Object.keys(pkg.peerDependenciesMeta ?? {}).sort(), Object.keys(PEERS).sort());
  for (const name of Object.keys(PEERS)) {
    assert.equal(pkg.peerDependenciesMeta[name].optional, true, `${name} must be an optional peer`);
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"])
      assert.equal(name in (pkg[field] ?? {}), false, `${name} must not be in ${field}`);
  }
});

test("missing-peers.mjs lists the same four peers and ranges as package.json, and the install command has all four", () => {
  assert.deepEqual({ ...OPTIONAL_PEERS }, pkg.peerDependencies);
  for (const [name, range] of Object.entries(pkg.peerDependencies)) assert.ok(INSTALL_COMMAND.includes(`"${name}@${range}"`), name);
  assert.ok(INSTALL_COMMAND.startsWith("npm install "));
  assert.deepEqual([...KIT_PEERS], ["rxjs", "@ledgerhq/context-module"]);
});

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (name.endsWith(".mjs") && !name.endsWith(".test.mjs")) out.push(p);
  }
  return out;
}

test("every bare import in src/device is a declared peer or a Node built-in, and every peer is used", () => {
  const files = walk(HERE);
  const names = files.map((f) => relative(HERE, f).split("\\").join("/"));
  assert.ok(names.includes("speculos-approver.mjs") && names.includes("index.mjs"), "the files where the test looks for imports");
  const used = new Set();
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    const specs = [
      ...text.matchAll(/^\s*(?:import|export)\s+(?:[\w*\s{},$]+?\s+from\s+)?['"]([^'"]+)['"]/gm),
      ...text.matchAll(/\b(?:require|import)\(\s*['"]([^'"]+)['"]\s*\)/g),
    ].map((m) => m[1]);
    for (const spec of specs) {
      if (spec.startsWith(".") || spec.startsWith("node:")) continue;
      const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
      assert.ok(name in (pkg.peerDependencies ?? {}), `${relative(HERE, f)} imports ${spec}, which package.json does not declare as a peer`);
      used.add(name);
    }
  }
  assert.deepEqual([...used].sort(), Object.keys(pkg.peerDependencies ?? {}).sort(), "a declared peer that no device file imports");
});

test("the exports map: ./device is the wrapper, the main entries are not, and every target exists", () => {
  assert.equal(pkg.exports["./device"], "./src/device/index.mjs");
  assert.deepEqual(
    { ".": pkg.exports["."], "./payer": pkg.exports["./payer"], "./audit": pkg.exports["./audit"] },
    { ".": "./index.js", "./payer": "./src/payer/index.js", "./audit": "./src/audit/index.js" },
  );
  for (const [sub, target] of Object.entries(pkg.exports))
    assert.ok(existsSync(join(ROOT, target)), `exports["${sub}"] -> ${target} does not exist`);
});

function exportedNames(file) {
  const text = readFileSync(file, "utf8");
  const names = [...text.matchAll(/^export\s+(?:async\s+)?(?:function\*?|const|let|class)\s+(\w+)/gm)].map((m) => m[1]);
  for (const [, list] of text.matchAll(/^export\s+(?:const|let)\s*\{([^}]*)\}\s*=/gm))
    names.push(...list.split(",").map((s) => s.trim().split(":").pop().trim()).filter(Boolean));
  return names.sort();
}

test("index.mjs re-exports every public name of speculos-approver.mjs, and no other", () => {
  const approver = exportedNames(join(HERE, "speculos-approver.mjs"));
  assert.deepEqual(approver, ["DEFAULT_ETH_PATH", "connectSpeculosApprover"], "the parser found the approver's exports");
  assert.deepEqual(exportedNames(join(HERE, "index.mjs")), approver);
});

test("files is an allowlist of things that exist, with secrets, logs, node_modules, tests and test support excluded", () => {
  assert.deepEqual(pkg.files, FILES);
  for (const f of pkg.files.filter((entry) => !entry.startsWith("!"))) assert.ok(existsSync(join(ROOT, f)), `files lists ${f}, which does not exist`);
});

// -------------------------------------------------------------- what npm packs

function npmCli() {
  const fromEnv = process.env.npm_execpath;
  if (fromEnv && /npm-cli\.js$/.test(fromEnv) && existsSync(fromEnv)) return fromEnv;
  const bundled = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  return existsSync(bundled) ? bundled : null;
}
const NPM = npmCli();
const NO_NPM = NPM ? false : "npm was not found next to this node; npm pack tests skipped";

/** The paths `npm pack --dry-run` would put in the tarball (no network, nothing written). */
function packed(cwd) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, [NPM, "pack", "--dry-run", "--json", "--ignore-scripts"], { cwd, env, encoding: "utf8", timeout: 90_000 });
  assert.equal(r.status, 0, `npm pack failed: ${r.stderr}`);
  return JSON.parse(r.stdout)[0].files.map((f) => f.path).sort();
}

test("npm pack leaves out stray secrets, logs, node_modules, tests and test support, and keeps ordinary files", { skip: NO_NPM }, () => {
  const tmp = mkdtempSync(join(tmpdir(), "spend-gate-pack-"));
  try {
    const put = (rel, text = "x\n") => {
      mkdirSync(dirname(join(tmp, rel)), { recursive: true });
      writeFileSync(join(tmp, rel), text);
    };
    writeFileSync(join(tmp, "package.json"), JSON.stringify(pkg));
    for (const ok of ["index.js", "src/ok.js", "src/deep/ok.js", "src/device/ok.mjs"]) put(ok);
    const strays = [".env", ".env.local", ".env.production", ".envrc", "server.pem", "deploy.key", "id_rsa", "id_rsa.pub", "secrets.json", "secrets.yaml",
      "npm-debug.log", "run.log", "node_modules/pkg/package.json", "thing.test.mjs"];
    for (const dir of ["", "src/", "src/deep/"]) for (const s of strays) put(dir + s);
    put("src/device/test-support/run-with-blocker.mjs");
    put("notes-for-me.txt"); // not in the allowlist
    assert.deepEqual(packed(tmp), ["index.js", "package.json", "src/deep/ok.js", "src/device/ok.mjs", "src/ok.js"]);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// What the four entries import, from source: static `import ... from "./x"`, `export ... from "./x"`, and `import("./x")`.
function reachableFrom(entries) {
  const seen = new Set();
  const queue = entries.map((e) => resolve(ROOT, e));
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const text = readFileSync(file, "utf8");
    const specs = [
      ...text.matchAll(/^\s*(?:import|export)\s+(?:[\w*\s{},$]+?\s+from\s+)?['"]([^'"]+)['"]/gm),
      ...text.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g),
    ].map((m) => m[1]);
    for (const spec of specs.filter((s) => s.startsWith("."))) queue.push(resolve(dirname(file), spec));
  }
  return [...seen].map((f) => relative(ROOT, f).split("\\").join("/")).sort();
}

test("npm pack ships every file the four entries import, and no test or test support", { skip: NO_NPM }, () => {
  const files = packed(ROOT);
  const needed = reachableFrom(Object.values({ main: "index.js", payer: "src/payer/index.js", audit: "src/audit/index.js", device: "src/device/index.mjs" }));
  assert.ok(needed.length >= 15 && needed.includes("src/device/speculos-approver.mjs") && needed.includes("src/device/missing-peers.mjs"), needed.join(", "));
  for (const f of needed) assert.ok(files.includes(f), `${f} is imported by an entry but not packed`);
  assert.deepEqual(files.filter((f) => /\.test\.mjs$|\/test-support\//.test(f)), []);
  for (const f of ["package.json", "README.md", "examples/basic.mjs"]) assert.ok(files.includes(f), f);
  assert.ok(!files.some((f) => posix.basename(f).startsWith(".env")));
});

// ---------------------------------------------- the explanation of a missing peer

test("missingPeerName and explainMissingPeer: which errors count as a missing peer", () => {
  const esm = (name) => Object.assign(new Error(`Cannot find package '${name}' imported from /x/speculos-approver.mjs`), { code: "ERR_MODULE_NOT_FOUND" });
  const cjs = (name) => Object.assign(new Error(`Cannot find module '${name}'\nRequire stack:\n- /x/speculos-approver.mjs`), { code: "MODULE_NOT_FOUND" });
  for (const name of [...Object.keys(OPTIONAL_PEERS), ...KIT_PEERS, "@ledgerhq/device-management-kit/lib/cjs/index.js", "rxjs/operators"]) {
    assert.equal(missingPeerName(esm(name)), name, `esm ${name}`);
    assert.equal(missingPeerName(cjs(name)), name, `cjs ${name}`);
    assert.equal(explainMissingPeer(cjs(name)).missing, name);
  }
  const notPeers = [
    esm("inversify"), cjs("@ledgerhq/context-module-evil"), cjs("rxjs2"), cjs("viem"), cjs("./x.js"),
    Object.assign(new Error("Cannot find module '/x/speculos-approver.mjs' imported from /x/index.mjs"), { code: "ERR_MODULE_NOT_FOUND" }),
    Object.assign(new Error("Cannot find package 'reflect-metadata' imported from /x"), { code: "ERR_UNSUPPORTED_DIR_IMPORT" }),
    Object.assign(new Error("Cannot find package 'reflect-metadata' imported from /x"), {}),
    new TypeError("Cannot find package 'reflect-metadata'"),
    Object.assign(new Error("Directory import 'reflect-metadata' is not supported"), { code: "ERR_MODULE_NOT_FOUND" }),
    null, undefined, "Cannot find package 'reflect-metadata'", 42,
  ];
  for (const e of notPeers) {
    assert.equal(missingPeerName(e), undefined, String(e?.message ?? e));
    assert.equal(explainMissingPeer(e), undefined, String(e?.message ?? e));
  }
});

test("the explanation lists all four optional peers, says they are optional, gives the install command, keeps the cause", () => {
  const cause = Object.assign(new Error("Cannot find package 'reflect-metadata' imported from /x"), { code: "ERR_MODULE_NOT_FOUND" });
  const error = explainMissingPeer(cause);
  assert.ok(error instanceof Error);
  assert.equal(error.cause, cause);
  assert.equal(error.code, "ERR_SPEND_GATE_DEVICE_PEERS");
  assert.equal(error.missing, "reflect-metadata");
  for (const [name, range] of Object.entries(PEERS)) assert.ok(error.message.includes(`${name} ${range}`), `lists ${name} ${range}`);
  assert.match(error.message, /optional peers/);
  assert.ok(error.message.includes(INSTALL_COMMAND));
  assert.match(error.message, /package-lock\.json/);
  assert.ok(error.message.includes("rxjs") && error.message.includes("@ledgerhq/context-module"));
});

// ------------------------------------- main entries and the wrapper, device blocked

// Imports are by file URL, so the result does not depend on the folder's path
// length (Node's package-scope lookup, which package self-reference uses, fails
// on paths over about 260 characters on Windows).
const PROBE = `
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
const root = process.cwd();
const out = { entries: {}, controls: {} };
const entries = { "index.js": "evaluate", "src/payer/index.js": "createPayer", "src/audit/index.js": "envelope" };
for (const [file, name] of Object.entries(entries)) {
  try { const m = await import(pathToFileURL(join(root, file)).href); out.entries[file] = typeof m[name]; }
  catch (e) { out.entries[file] = "FAILED " + (e.code ?? "") + " " + e.message; }
}
await new Promise((r) => setTimeout(r, 200));            // let the loader thread's reports arrive
out.blockedAfterEntries = [...globalThis.__blockedDevicePackages];
const require = createRequire(pathToFileURL(join(root, "probe.cjs")));
for (const spec of ["reflect-metadata", "@ledgerhq/device-management-kit", "@ledgerhq/device-signer-kit-ethereum", "@ledgerhq/device-transport-kit-speculos"]) {
  try { await import(spec); out.controls["import " + spec] = "loaded"; } catch (e) { out.controls["import " + spec] = e.code + " | " + e.message; }
  try { require(spec); out.controls["require " + spec] = "loaded"; } catch (e) { out.controls["require " + spec] = e.code + " | " + e.message; }
}
try { await import(pathToFileURL(join(root, "src/device/speculos-approver.mjs")).href); out.controls.device = "loaded"; }
catch (e) { out.controls.device = e.code + " | " + e.message; }
await new Promise((r) => setTimeout(r, 200));
out.blockedAll = [...globalThis.__blockedDevicePackages];
console.log("RESULT:" + JSON.stringify(out));
`;

let memo;
const probe = () => (memo ??= runProbe(PROBE));

test("index.js, the payer and the audit entry load with the device packages unable to resolve", async () => {
  const { entries, blockedAfterEntries } = await probe();
  assert.deepEqual(entries, {
    "index.js": "function",
    "src/payer/index.js": "function",
    "src/audit/index.js": "function",
  });
  assert.deepEqual(blockedAfterEntries, [], "loading the main entries must not even try to resolve a device package");
});

test("control: the blocker blocks, so the test above means something even where the packages are installed", async () => {
  const { controls, blockedAll } = await probe();
  for (const spec of ["reflect-metadata", "@ledgerhq/device-management-kit", "@ledgerhq/device-signer-kit-ethereum", "@ledgerhq/device-transport-kit-speculos"]) {
    assert.match(controls["import " + spec], /^ERR_MODULE_NOT_FOUND \|.*\[blocked by block-device-packages-hooks\.mjs\]$/, spec);
    assert.match(controls["require " + spec], /^MODULE_NOT_FOUND \|.*\[blocked by block-device-packages\.mjs\]$/, spec);
    assert.ok(blockedAll.includes("import " + spec), `import of ${spec} was not recorded`);
    assert.ok(blockedAll.includes("require " + spec), `require of ${spec} was not recorded`);
  }
  // And the device module, which needs them, fails to load under the blocker.
  assert.match(controls.device, /^ERR_MODULE_NOT_FOUND \| Cannot find package 'reflect-metadata' .*\[blocked by block-device-packages-hooks\.mjs\]$/);
});

test("control: a file inside a blocked package's folder is blocked by its path, for require and import; other folders are not", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "spend-gate-blocker-"));
  try {
    const put = (rel, text) => {
      mkdirSync(dirname(join(tmp, rel)), { recursive: true });
      writeFileSync(join(tmp, rel), text);
    };
    put("node_modules/@ledgerhq/fake-kit/index.cjs", "module.exports = 1;\n");
    put("node_modules/@ledgerhq/fake-kit/index.mjs", "export default 1;\n");
    put("node_modules/other-pkg/index.cjs", "module.exports = 1;\n");
    put("node_modules/other-pkg/index.mjs", "export default 1;\n");
    const out = await runProbe(`
      import { createRequire } from "node:module";
      import { pathToFileURL } from "node:url";
      import { join } from "node:path";
      const dir = process.env.PROBE_DIR;
      const require = createRequire(pathToFileURL(join(dir, "probe.cjs")));
      const out = {};
      const tryRequire = (key, rel) => { try { require(join(dir, rel)); out[key] = "loaded"; } catch (e) { out[key] = e.code + " | " + e.message.split("\\n")[0]; } };
      const tryImport = async (key, rel) => { try { await import(pathToFileURL(join(dir, rel)).href); out[key] = "loaded"; } catch (e) { out[key] = e.code + " | " + e.message.split("\\n")[0]; } };
      tryRequire("requireBlocked", "node_modules/@ledgerhq/fake-kit/index.cjs");
      await tryImport("importBlocked", "node_modules/@ledgerhq/fake-kit/index.mjs");
      tryRequire("requireOther", "node_modules/other-pkg/index.cjs");
      await tryImport("importOther", "node_modules/other-pkg/index.mjs");
      console.log("RESULT:" + JSON.stringify(out));
    `, { PROBE_DIR: tmp });
    assert.match(out.requireBlocked, /^MODULE_NOT_FOUND \| Cannot find module .*fake-kit.* \[blocked by block-device-packages\.mjs\]$/);
    assert.match(out.importBlocked, /^ERR_MODULE_NOT_FOUND \| Cannot find package .*fake-kit.* \[blocked by block-device-packages-hooks\.mjs\]$/);
    assert.equal(out.requireOther, "loaded");
    assert.equal(out.importOther, "loaded");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("spend-gate/device (index.mjs) with the peers missing throws one error: all four peers, optional, the install command, the cause", async () => {
  const out = await runProbe(WRAPPER_PROBE);
  assert.equal(out.threw, true, JSON.stringify(out));
  assert.equal(out.code, "ERR_SPEND_GATE_DEVICE_PEERS");
  assert.equal(out.missing, "reflect-metadata");
  for (const [name, range] of Object.entries(PEERS)) assert.ok(out.message.includes(`${name} ${range}`), `lists ${name} ${range}`);
  assert.match(out.message, /optional peers/);
  assert.ok(out.message.includes(INSTALL_COMMAND));
  assert.equal(out.hasCause, true);
  assert.equal(out.causeCode, "ERR_MODULE_NOT_FOUND");
  assert.match(out.causeMessage, /^Cannot find package 'reflect-metadata'/);
});

test("spend-gate/device rethrows an error that is not a missing peer unchanged", async () => {
  const out = await runProbe(WRAPPER_PROBE, { BLOCK_DEVICE_PACKAGES_THROW: "other" });
  assert.equal(out.threw, true, JSON.stringify(out));
  assert.equal(out.code, "ERR_TEST_BOOM");
  assert.match(out.message, /^boom \(not a missing-package error\)/);
  assert.equal(out.hasCause, false);
  assert.equal(out.missing, undefined);
});

test("require() of the wrapper fails because of its top-level await, so CommonJS callers use import(); the other entries can be required", () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const required = (file) => {
    const code = `try { require(${JSON.stringify(file)}); console.log("RESULT:loaded"); } catch (e) { console.log("RESULT:" + e.code); }`;
    const r = spawnSync(process.execPath, ["-e", code], { cwd: ROOT, env, encoding: "utf8", timeout: 60_000 });
    return (r.stdout.match(/^RESULT:(.*)$/m) ?? [])[1] ?? `no result (exit ${r.status}): ${r.stderr}`;
  };
  const wrapper = required("./src/device/index.mjs");
  assert.match(wrapper, /^(ERR_REQUIRE_ASYNC_MODULE|ERR_REQUIRE_ESM)$/, wrapper);
  // Only where require() of an ES module is available at all (Node 22.12 and later) can the others be required.
  if (wrapper === "ERR_REQUIRE_ASYNC_MODULE") for (const file of ["./index.js", "./src/payer/index.js", "./src/audit/index.js"]) assert.equal(required(file), "loaded", file);
});

// ------------------------------------------------- SPEND_GATE_REQUIRE_DEVICE

// Run speculos-approver.test.mjs itself, as a child, where the device packages cannot resolve.
const deviceTestFile = ["src/device/speculos-approver.test.mjs"];

test("without SPEND_GATE_REQUIRE_DEVICE the device test skips (one skip, exit 0) when the peers are missing", async () => {
  for (const value of [undefined, "", "0"]) {
    const r = await spawnBlocked(deviceTestFile, { SPEND_GATE_REQUIRE_DEVICE: value });
    const text = r.stdout + r.stderr;
    assert.equal(r.status, 0, `value ${JSON.stringify(value)}: ${text}`);
    assert.match(text, /skipped 1\b/i, text);
    assert.match(text, /device packages not installed \(missing: reflect-metadata/);
    assert.match(text, /fail 0\b/i);
  }
});

test("with SPEND_GATE_REQUIRE_DEVICE=1 the device test fails, with the missing packages and the install command", async () => {
  const r = await spawnBlocked(deviceTestFile, { SPEND_GATE_REQUIRE_DEVICE: "1" });
  const text = r.stdout + r.stderr;
  assert.notEqual(r.status, 0, text);
  assert.match(text, /SPEND_GATE_REQUIRE_DEVICE=1 and device packages not installed \(missing: reflect-metadata, @ledgerhq\/device-management-kit, @ledgerhq\/device-signer-kit-ethereum, @ledgerhq\/device-transport-kit-speculos\)/);
  assert.ok(text.includes(INSTALL_COMMAND), text);
  assert.match(text, /skipped 0\b/i);
  assert.match(text, /fail 1\b/i);
});

test("package.json has test:device, which sets the switch from node (no shell syntax)", () => {
  assert.equal(pkg.scripts["test:device"], "node src/device/test-support/run-device-tests.mjs");
  const runner = readFileSync(join(HERE, "test-support", "run-device-tests.mjs"), "utf8");
  assert.match(runner, /SPEND_GATE_REQUIRE_DEVICE: "1"/);
  assert.match(runner, /src\/device\/\*\.test\.mjs/);
  assert.ok(existsSync(join(HERE, "test-support", "run-device-tests.mjs")));
});
