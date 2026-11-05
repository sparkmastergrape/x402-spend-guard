// What to tell a developer who imports `spend-gate/device` without the optional
// peer packages. Used by index.mjs. Pure: no I/O, and it loads none of the
// packages it names.

/** The optional peers, as package.json declares them (a test checks the two agree). */
export const OPTIONAL_PEERS = Object.freeze({
  "@ledgerhq/device-management-kit": "^1.11.0",
  "@ledgerhq/device-signer-kit-ethereum": "^1.18.2",
  "@ledgerhq/device-transport-kit-speculos": "^1.3.0",
  "reflect-metadata": "^0.2.2",
});

/** Required peers of the Ledger kits, not declared by spend-gate; npm installs them with the command below. */
export const KIT_PEERS = Object.freeze(["rxjs", "@ledgerhq/context-module"]);

/** Quoted, so it also works in cmd.exe, where an unquoted ^ is an escape character. */
export const INSTALL_COMMAND = `npm install ${Object.entries(OPTIONAL_PEERS)
  .map(([name, range]) => `"${name}@${range}"`)
  .join(" ")}`;

/**
 * The name of the package a "not found" error is about, when that package is one
 * of the optional peers or a required peer of the kits. Otherwise undefined: not
 * a not-found error, a missing file, or a missing package of something else.
 */
export function missingPeerName(error) {
  if (!error || typeof error !== "object") return undefined;
  if (error.code !== "ERR_MODULE_NOT_FOUND" && error.code !== "MODULE_NOT_FOUND") return undefined;
  // ESM: "Cannot find package 'x' imported from ..."; CommonJS: "Cannot find module 'x'" + a require stack.
  const named = /^Cannot find (?:package|module) '([^']+)'/.exec(String(error.message));
  if (!named) return undefined;
  const name = named[1];
  const known = [...Object.keys(OPTIONAL_PEERS), ...KIT_PEERS];
  return known.some((peer) => name === peer || name.startsWith(`${peer}/`)) ? name : undefined;
}

/** One Error to throw in place of a missing-peer error, or undefined when `error` is not one. */
export function explainMissingPeer(error) {
  const missing = missingPeerName(error);
  if (missing === undefined) return undefined;
  const lines = [
    `spend-gate/device needs packages that are not installed (cannot find '${missing}').`,
    "It needs these four, which spend-gate declares as optional peers, so a plain `npm install` does not install them:",
    ...Object.entries(OPTIONAL_PEERS).map(([name, range]) => `  ${name} ${range}`),
    "Install them with:",
    `  ${INSTALL_COMMAND}`,
    `The rest of spend-gate works without them. npm also installs the Ledger kits' own required peers (${KIT_PEERS.join(", ")}).`,
    "If npm answers \"up to date\" and installs nothing, delete package-lock.json and run the command again.",
  ];
  return Object.assign(new Error(lines.join("\n"), { cause: error }), {
    code: "ERR_SPEND_GATE_DEVICE_PEERS",
    missing,
  });
}
