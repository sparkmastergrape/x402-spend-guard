// `spend-gate/device`: the entry for the Ledger/Speculos approver.
//
// speculos-approver.mjs needs four optional peer packages (see package.json). When
// one is missing, a bare ERR_MODULE_NOT_FOUND or a CommonJS require stack does not
// say what to install, so this wrapper turns that one case into a single error
// that lists all four and the install command. Every other error is rethrown
// unchanged. Nothing else in the package imports this file.

import { explainMissingPeer } from "./missing-peers.mjs";

let device;
try {
  device = await import("./speculos-approver.mjs");
} catch (error) {
  throw explainMissingPeer(error) ?? error;
}

// Every public name of speculos-approver.mjs (a test compares the two lists).
export const { connectSpeculosApprover, DEFAULT_ETH_PATH } = device;
