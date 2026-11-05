// Test support for the device tests. Not part of the package's public surface
// (nothing exports it, and it is not packed).
//
// The resolve hook that makes the device packages "not installed", whether or not
// they are. It runs on Node's loader thread, registered by
// block-device-packages.mjs, which also imports the helpers below for `require`.
//
// Environment, read by both threads:
//   BLOCK_DEVICE_PACKAGES_ONLY=a,b   block only these packages (default: @ledgerhq/* and
//                                    reflect-metadata; rxjs, a required peer of the kits,
//                                    is blocked only when named here)
//   BLOCK_DEVICE_PACKAGES_THROW=other  fail with an error that is NOT a not-found
//                                      error, to test that such an error passes through

const PACKAGE = /^(@ledgerhq\/[^/]+|reflect-metadata|rxjs)(?:\/|$)/;
const IN_NODE_MODULES = /[\\/]node_modules[\\/](@ledgerhq[\\/][^\\/]+|reflect-metadata|rxjs)(?:[\\/]|$)/;

const only = () => (process.env.BLOCK_DEVICE_PACKAGES_ONLY ? process.env.BLOCK_DEVICE_PACKAGES_ONLY.split(",") : null);
const selected = (name) => (only() ? only().includes(name) : name !== "rxjs");

/** The blocked package a bare specifier names, or undefined. */
export function blockedSpecifier(specifier) {
  const name = PACKAGE.exec(specifier)?.[1];
  return name && selected(name) ? name : undefined;
}

/** The blocked package a resolved file path or URL lies in, or undefined. */
export function blockedPath(pathOrUrl) {
  const name = IN_NODE_MODULES.exec(pathOrUrl)?.[1]?.replace("\\", "/");
  return name && selected(name) ? name : undefined;
}

/** The error to throw: "not found" by default, or an unrelated one in `other` mode. */
export function blockedError(kind, what, parent) {
  if (process.env.BLOCK_DEVICE_PACKAGES_THROW === "other")
    return Object.assign(new Error(`boom (not a missing-package error) for ${what} [block-device-packages]`), { code: "ERR_TEST_BOOM" });
  if (kind === "esm")
    return Object.assign(
      new Error(`Cannot find package '${what}' imported from ${parent ?? "(unknown)"} [blocked by block-device-packages-hooks.mjs]`),
      { code: "ERR_MODULE_NOT_FOUND" },
    );
  return Object.assign(new Error(`Cannot find module '${what}' [blocked by block-device-packages.mjs]`), { code: "MODULE_NOT_FOUND" });
}

let port;

export function initialize(data) {
  port = data?.port;
}

export async function resolve(specifier, context, nextResolve) {
  if (blockedSpecifier(specifier)) {
    port?.postMessage(specifier);
    throw blockedError("esm", specifier, context.parentURL);
  }
  const result = await nextResolve(specifier, context);
  if (blockedPath(result.url)) {
    port?.postMessage(result.url);
    throw blockedError("esm", result.url, context.parentURL);
  }
  return result;
}
