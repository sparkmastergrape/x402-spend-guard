// Test support for the device tests. Not part of the package's public surface
// (nothing exports it, and it is not packed).
//
//   node --import <file URL of this file> ...
//
// makes the device packages (@ledgerhq/*, reflect-metadata) fail to resolve for
// both an ES module `import` (a resolve hook, block-device-packages-hooks.mjs)
// and a CommonJS `require` (Module._resolveFilename, which is how
// speculos-approver.mjs loads the Ledger kits). They fail whether or not the
// packages are installed, so a test run under this file means the same thing on a
// machine that has them. Each stopped specifier is recorded in
// globalThis.__blockedDevicePackages as `import <spec>` or `require <spec>`.
// BLOCK_DEVICE_PACKAGES_ONLY and BLOCK_DEVICE_PACKAGES_THROW change what is
// blocked and how it fails; see the hooks file.
//
// `module.register` is used rather than `module.registerHooks` because the
// latter is missing from Node 22.13, the oldest version `engines` allows.

import Module, { register } from "node:module";
import { MessageChannel } from "node:worker_threads";
import { blockedError, blockedPath, blockedSpecifier } from "./block-device-packages-hooks.mjs";

const blocked = (globalThis.__blockedDevicePackages = []);

const { port1, port2 } = new MessageChannel();
port1.on("message", (spec) => blocked.push(`import ${spec}`));
port1.unref();
register("./block-device-packages-hooks.mjs", {
  parentURL: import.meta.url,
  data: { port: port2 },
  transferList: [port2],
});

const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (blockedSpecifier(request)) {
    blocked.push(`require ${request}`);
    throw blockedError("cjs", request);
  }
  const filename = resolveFilename.call(this, request, ...rest);
  if (blockedPath(filename)) {
    blocked.push(`require ${filename}`);
    throw blockedError("cjs", filename);
  }
  return filename;
};
