// speculos-approver.mjs and its entry index.mjs, offline. They need the optional
// device packages, so the whole file SKIPS (with the reason and the install
// command) when they are not installed, and the suite stays green on a machine
// without them. With SPEND_GATE_REQUIRE_DEVICE=1 (npm run test:device) the same
// situation FAILS instead, with the install command.
//
// What this file does: imports the module, checks its exports and the Ledger
// bindings it destructures, builds the DMK with the Speculos transport and
// discovers the emulator device with no emulator, drives connectSpeculosApprover
// against a small fake of Speculos' HTTP API (a node:http server on 127.0.0.1)
// down its error paths, and, with a fake that answers the app-info and
// get-address APDUs, checks that close() stops the transport's polling.
//
// What it does NOT do: talk to a real Speculos, an Ethereum app or a Ledger
// device. The fake shares my assumptions about the module and the transport:
// its screen strings are made up, the button-press sequence is the one I read in
// the source, and the APDU bodies it answers are the ones I saw the packages
// send. getAddress is only exercised against that canned answer; signTypedData,
// decide() and walkReview() never run. None of this shows the signing path works.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { runProbe, WRAPPER_PROBE } from "./test-support/run-with-blocker.mjs";
import { INSTALL_COMMAND, OPTIONAL_PEERS } from "./missing-peers.mjs";

const require = createRequire(import.meta.url);

const NEEDED = [
  "reflect-metadata",
  "@ledgerhq/device-management-kit",
  "@ledgerhq/device-signer-kit-ethereum",
  "@ledgerhq/device-transport-kit-speculos",
];
const missing = NEEDED.filter((name) => {
  try {
    require.resolve(name);
    return false;
  } catch {
    return true;
  }
});
// SPEND_GATE_REQUIRE_DEVICE=1: missing peers are a failure, not a skip.
const REQUIRE = process.env.SPEND_GATE_REQUIRE_DEVICE === "1";
const WHY = `device packages not installed (missing: ${missing.join(", ")}); to run these tests: ${INSTALL_COMMAND}`;
const SKIP = missing.length && !REQUIRE ? WHY : false;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ------------------------------------------------------------ a fake Speculos

const SCREEN = {
  home: "Ethereum app is ready",
  settings: "App settings",
  rawOff: "Raw messages | Disabled",
  rawOn: "Raw messages | Enabled",
  quit: "Quit app",
  other: "Version | 1.0.0",
};

/**
 * The few Speculos HTTP endpoints the module's error paths touch:
 * GET /events (the screen), POST /button/<key>, POST /automation, POST /apdu.
 *
 *   stuck        the screen is always "Quit app": the app never gets home
 *   no-settings  home, then a screen that never becomes "App settings"
 *   toggle-stuck home -> App settings -> "Raw messages | Disabled", which a press never changes
 *   toggle-ok    the same, but a press makes it "Enabled"; then every /apdu answers HTTP 500
 *   address      the same, but /apdu answers an app-info reply ("Ethereum 1.0.0", status 9000)
 *                and, for a get-address APDU (INS e0 02), a canned address reply
 */
const hex = (text) => Buffer.from(text).toString("hex");
const APP_INFO = "01" + "08" + hex("Ethereum") + "05" + hex("1.0.0") + "9000";
const FAKE_ADDRESS = "11".repeat(20);
const ADDRESS_REPLY = "41" + "04" + "ab".repeat(64) + "28" + hex(FAKE_ADDRESS) + "9000";

async function fakeSpeculos(mode) {
  const requests = [];
  let screen = mode === "stuck" ? "quit" : "home";
  const press = (key) => {
    if (mode === "no-settings") {
      if (key === "right") screen = screen === "home" ? "other" : "home";
      return;
    }
    if (screen === "home" && key === "right") screen = "settings";
    else if (screen === "settings" && key === "both") screen = "rawOff";
    else if (screen === "settings" && key === "left") screen = "home";
    else if (screen === "rawOff" && key === "both" && (mode === "toggle-ok" || mode === "address")) screen = "rawOn";
    else if ((screen === "rawOff" || screen === "rawOn") && key === "right") screen = "settings";
  };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      requests.push({ method: req.method, path: req.url, body });
      const send = (status, text) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(text);
      };
      if (req.method === "GET" && req.url.startsWith("/events"))
        return send(200, JSON.stringify({ events: [{ text: SCREEN[screen] }] }));
      if (req.method === "POST" && req.url.startsWith("/button/")) {
        press(req.url.split("/")[2]);
        return send(200, "{}");
      }
      if (req.method === "POST" && req.url === "/automation") return send(200, "{}");
      if (req.method === "POST" && req.url === "/apdu") {
        if (mode !== "address") return send(500, "{}");
        const apdu = String(JSON.parse(body).data).toLowerCase();
        return send(200, JSON.stringify({ data: apdu.startsWith("e002") ? ADDRESS_REPLY : APP_INFO }));
      }
      send(404, "{}");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

async function closedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

function installTripwires(attempts) {
  const realFetch = globalThis.fetch;
  const realConnect = net.Socket.prototype.connect;
  const realLookup = dns.lookup;
  globalThis.fetch = (input) => {
    attempts.push(`fetch ${input}`);
    return Promise.reject(new Error("tripwire: fetch"));
  };
  net.Socket.prototype.connect = function () {
    attempts.push("net.Socket.connect");
    throw new Error("tripwire: socket");
  };
  dns.lookup = (host) => {
    attempts.push(`dns.lookup ${host}`);
    throw new Error("tripwire: dns");
  };
  return () => {
    globalThis.fetch = realFetch;
    net.Socket.prototype.connect = realConnect;
    dns.lookup = realLookup;
  };
}

// ---------------------------------------------------------------------- tests

test(
  "src/device/speculos-approver.mjs with the optional device packages installed (offline)",
  { skip: SKIP, concurrency: true },
  async (t) => {
    // Only reachable with SPEND_GATE_REQUIRE_DEVICE=1 (otherwise the test is skipped above).
    if (missing.length) assert.fail(`SPEND_GATE_REQUIRE_DEVICE=1 and ${WHY}`);

    // DMK's ConsoleLogger prints "[ConnectUseCase] Error connecting to device" on the error path below.
    t.mock.method(console, "error", () => {});
    t.mock.method(console, "warn", () => {});

    // The first import of the module in this process, with every outbound route trapped.
    const attempts = [];
    const undo = installTripwires(attempts);
    let mod;
    try {
      mod = await import("./speculos-approver.mjs");
    } finally {
      undo();
    }
    // From here on, record fetches without blocking them (subtests filter by their own URL).
    const fetched = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (input, init) => {
      fetched.push(`${init?.method ?? "GET"} ${input}`);
      return realFetch(input, init);
    };
    t.after(() => {
      globalThis.fetch = realFetch;
    });

    const subs = [];
    const sub = (name, fn) => subs.push(t.test(name, fn));

    sub("importing it makes no connection, DNS lookup or fetch: no emulator is needed to import", () => {
      assert.deepEqual(attempts, []);
    });

    sub("it exports connectSpeculosApprover (async) and DEFAULT_ETH_PATH, and nothing else", () => {
      assert.deepEqual(Object.keys(mod).sort(), ["DEFAULT_ETH_PATH", "connectSpeculosApprover"]);
      assert.equal(mod.DEFAULT_ETH_PATH, "44'/60'/0'/0/0");
      assert.equal(mod.connectSpeculosApprover.constructor.name, "AsyncFunction");
    });

    sub("every name the module destructures from a Ledger package exists there (a missing one would only show as undefined)", () => {
      // Read from the module's own source, so a typo in it or a rename in a package release is caught.
      const source = readFileSync(new URL("./speculos-approver.mjs", import.meta.url), "utf8");
      const found = [...source.matchAll(/const\s*\{([^}]*)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g)];
      const names = [];
      for (const [, list, pkg] of found) {
        const loaded = require(pkg);
        for (const name of list.split(",").map((s) => s.trim().split(":")[0].trim()).filter(Boolean)) {
          assert.notEqual(loaded[name], undefined, `${pkg} has no export ${name}`);
          names.push(name);
        }
      }
      assert.deepEqual(names.sort(), [
        "ConsoleLogger", "DeviceActionStatus", "DeviceManagementKitBuilder", "DeviceModelId", "LogLevel",
        "SignerEthBuilder", "speculosTransportFactory",
      ]);

      const dmk = require("@ledgerhq/device-management-kit");
      const speculos = require("@ledgerhq/device-transport-kit-speculos");
      const eth = require("@ledgerhq/device-signer-kit-ethereum");
      for (const name of ["ConsoleLogger", "DeviceManagementKitBuilder"]) assert.equal(typeof dmk[name], "function", name);
      assert.equal(typeof speculos.speculosTransportFactory, "function");
      assert.equal(typeof eth.SignerEthBuilder, "function");
      assert.equal(typeof dmk.DeviceModelId.NANO_X, "string");
      assert.equal(typeof dmk.LogLevel.Warning, "number");
      for (const state of ["Completed", "Error", "Stopped"])
        assert.equal(typeof dmk.DeviceActionStatus[state], "string", `DeviceActionStatus.${state}`);
      // The builder the module calls on a session, and the two methods it then uses, on a DMK with
      // no transport and a session id that was never opened (building a signer does not talk to a device).
      const signer = new eth.SignerEthBuilder({ dmk: new dmk.DeviceManagementKitBuilder().build(), sessionId: "never-opened" }).build();
      assert.equal(typeof signer.getAddress, "function");
      assert.equal(typeof signer.signTypedData, "function");
    });

    sub("the DMK builds with the Speculos transport and discovers its device with no emulator; only connect needs one", async () => {
      const { DeviceManagementKitBuilder, DeviceModelId } = require("@ledgerhq/device-management-kit");
      const { speculosTransportFactory } = require("@ledgerhq/device-transport-kit-speculos");
      const url = `http://127.0.0.1:${await closedPort()}`;
      const dmk = new DeviceManagementKitBuilder()
        .addTransport(speculosTransportFactory(url, false, DeviceModelId.NANO_X))
        .build();
      const device = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("no device discovered in 3s")), 3000);
        dmk.startDiscovering({}).subscribe({
          next: (d) => (clearTimeout(timer), resolve(d)),
          error: (e) => (clearTimeout(timer), reject(e)),
        });
      });
      assert.ok(device);
      assert.deepEqual(fetched.filter((f) => f.includes(url)), [], "building and discovering must not touch the network");
      await assert.rejects(dmk.connect({ device }));
      assert.deepEqual(fetched.filter((f) => f.includes(url)), [`POST ${url}/apdu`]);
    });

    sub("an emulator that is not running rejects the call, with the connection error", async () => {
      const url = `http://127.0.0.1:${await closedPort()}`;
      await assert.rejects(mod.connectSpeculosApprover({ url }), (e) => {
        assert.ok(e instanceof Error);
        assert.match(String(e.message), /fetch failed/i);
        return true;
      });
    });

    sub("a url that is not a URL rejects the call", async () => {
      await assert.rejects(mod.connectSpeculosApprover({ url: "not a url" }), TypeError);
    });

    sub("with no url argument it reads SPECULOS_URL; the first thing it does is clear Speculos' automation rules", async () => {
      const fake = await fakeSpeculos("toggle-stuck");
      const saved = process.env.SPECULOS_URL;
      process.env.SPECULOS_URL = fake.url;
      try {
        await assert.rejects(mod.connectSpeculosApprover({}), /Raw messages toggle did not take/);
      } finally {
        if (saved === undefined) delete process.env.SPECULOS_URL;
        else process.env.SPECULOS_URL = saved;
        await fake.close();
      }
      assert.deepEqual(fake.requests[0], { method: "POST", path: "/automation", body: '{"version":1,"rules":[]}' });
      // It pressed "both" on the Disabled row, read it again, saw it unchanged, and stopped.
      const presses = fake.requests.filter((r) => r.path.startsWith("/button/")).map((r) => r.path);
      assert.deepEqual(presses, ["/button/right", "/button/both", "/button/both"]);
    });

    sub("when Raw messages gets enabled it carries on to the DMK; with the fake refusing APDUs it rejects at connect", async () => {
      const fake = await fakeSpeculos("toggle-ok");
      const logs = [];
      try {
        await assert.rejects(mod.connectSpeculosApprover({ url: fake.url, log: (s) => logs.push(s) }));
      } finally {
        await fake.close();
      }
      assert.deepEqual(logs, ["Raw messages -> Enabled"]);
      const last = fake.requests.at(-1);
      assert.deepEqual(last, { method: "POST", path: "/apdu", body: '{"data":"B0010000"}' }, "the first APDU is the app-info query");
      assert.equal(fake.requests.filter((r) => r.path === "/apdu").length, 1);
      assert.equal(fake.requests[0].path, "/automation", "automation is cleared before anything else");
    });

    sub("if the app never reaches App settings it says so, with the last screen", async () => {
      const fake = await fakeSpeculos("no-settings");
      try {
        await assert.rejects(
          mod.connectSpeculosApprover({ url: fake.url }),
          /could not reach App settings; last screen: (Version \| 1\.0\.0|Ethereum app is ready)/,
        );
      } finally {
        await fake.close();
      }
    });

    sub("if the app never reaches the home screen it says so, with the screen it is stuck on (about 6 s)", async () => {
      const fake = await fakeSpeculos("stuck");
      try {
        await assert.rejects(mod.connectSpeculosApprover({ url: fake.url }), /could not reach home; stuck at: Quit app/);
      } finally {
        await fake.close();
      }
      // "Quit app" is read as a screen to walk away from with "left", never confirmed with "both".
      const keys = new Set(fake.requests.filter((r) => r.path.startsWith("/button/")).map((r) => r.path));
      assert.deepEqual([...keys], ["/button/left"]);
    });

    sub("index.mjs (spend-gate/device) exports exactly what the approver exports, as the same values", async () => {
      const entry = await import("./index.mjs");
      assert.deepEqual(Object.keys(entry).sort(), Object.keys(mod).sort());
      for (const name of Object.keys(mod)) assert.strictEqual(entry[name], mod[name], name);
    });

    // One peer at a time made unresolvable (the others stay installed): the entry names it and lists all four.
    for (const [peer, how] of [
      ["reflect-metadata", "an ES module import"],
      ["@ledgerhq/device-management-kit", "a require"],
      ["@ledgerhq/device-signer-kit-ethereum", "a require"],
      ["@ledgerhq/device-transport-kit-speculos", "a require"],
      ["@ledgerhq/context-module", "a require inside the signer kit"],
      ["rxjs", "a require inside the DMK"],
    ]) {
      sub(`index.mjs with only ${peer} missing (${how}) throws the one clear error, naming it`, async () => {
        const out = await runProbe(WRAPPER_PROBE, { BLOCK_DEVICE_PACKAGES_ONLY: peer });
        assert.equal(out.threw, true, JSON.stringify(out));
        assert.equal(out.code, "ERR_SPEND_GATE_DEVICE_PEERS");
        assert.equal(out.missing, peer);
        assert.match(out.message, new RegExp(`cannot find '${peer.replace(/[/@]/g, "\\$&")}'`));
        for (const name of Object.keys(OPTIONAL_PEERS)) assert.ok(out.message.includes(name), `message lists ${name}`);
        assert.ok(out.message.includes(INSTALL_COMMAND));
        assert.equal(out.hasCause, true);
        assert.match(out.causeCode, /^(ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND)$/);
      });
    }

    sub("with the fake answering the app-info and get-address APDUs it connects, and close() in a finally block stops the polling", async () => {
      const fake = await fakeSpeculos("address");
      let approver;
      try {
        try {
          approver = await mod.connectSpeculosApprover({ url: fake.url });
          assert.equal(approver.address, `0x${FAKE_ADDRESS}`);
          const mark = fake.requests.length;
          await sleep(2600);
          assert.ok(fake.requests.length > mark, "while the session is open the DMK and the transport keep polling");
        } finally {
          await approver?.close();
        }
        const closed = fake.requests.length;
        await sleep(2600);
        assert.equal(fake.requests.length, closed, "after close() nothing is requested any more");
      } finally {
        await fake.close();
      }
    });

    await Promise.all(subs);

    // After the concurrent group, so the global fetch stub below cannot disturb it.
    await t.test("with no url argument and no SPECULOS_URL it goes to http://localhost:5010 (fetch stubbed, nothing is sent)", async (st) => {
      const saved = process.env.SPECULOS_URL;
      delete process.env.SPECULOS_URL;
      const urls = [];
      st.mock.method(globalThis, "fetch", (input, init) => {
        urls.push(`${init?.method ?? "GET"} ${input}`);
        return Promise.reject(new Error("stubbed fetch: no network"));
      });
      try {
        await assert.rejects(mod.connectSpeculosApprover({}), /stubbed fetch/);
      } finally {
        if (saved !== undefined) process.env.SPECULOS_URL = saved;
      }
      assert.deepEqual(urls.slice(0, 2), [
        "POST http://localhost:5010/automation",
        "GET http://localhost:5010/events?currentscreenonly=true",
      ]);
    });
  },
);
