// `npm run test:device`: run the tests in src/device/ with
// SPEND_GATE_REQUIRE_DEVICE=1, so that missing device packages make the device
// test FAIL (with the install command) instead of skipping. A tiny node script,
// not `SPEND_GATE_REQUIRE_DEVICE=1 node --test ...`, because that syntax differs
// between cmd.exe, PowerShell and sh. Test support: not packed.

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const env = { ...process.env, SPEND_GATE_REQUIRE_DEVICE: "1" };
delete env.NODE_TEST_CONTEXT;

// node expands the glob itself (Node 22 and later), so no shell is involved.
const child = spawn(process.execPath, ["--test", "--test-reporter=spec", "src/device/*.test.mjs"], {
  cwd: root,
  env,
  stdio: "inherit",
});
child.on("error", (error) => {
  console.error(`could not start node --test: ${error.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
