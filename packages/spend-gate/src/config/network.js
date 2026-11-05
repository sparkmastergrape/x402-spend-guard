// Verified network constants. Every value here was read from
// GET /public/x402-context (authoritative, unauthenticated) and confirmed
// on-chain on 2026-10-25.
//
// Do not edit by hand from memory — re-read /public/x402-context and the chain.

/**
 * XRPL EVM **Testnet**.
 *
 * 1440000 is MAINNET. The testnet is 1449000. Because chainId sits inside the EIP-712 domain separator, using the wrong one
 * produces signatures bound to the wrong network that still verify locally.
 */
export const CHAIN_ID = 1449000;
export const CHAIN_ID_MAINNET_DO_NOT_USE = 1440000;

export const RPC_URL = "https://rpc.testnet.xrplevm.org";
export const GAS_FAUCET = "https://faucet.xrplevm.org";

/** RLUSD on XRPL EVM Testnet. 18 decimals — confirmed by `decimals()`. */
export const RLUSD = "0x27b57a9D0b8d24EB97259c4E2279e45255e016f3";
export const RLUSD_DECIMALS = 18;

/** AP4M PaymentLedger — vouchers are redeemed here, and it is the EIP-712 verifyingContract for a Voucher. */
export const PAYMENT_LEDGER = "0xcAB42800A5ECF0D253Fa2581Bb3334B4DAEfaE91";
export const VAULT = "0x83DD9cD010eb46e96eceF8F7eB0a18f7845AaBC0";

export const AP4M_API_URL = "https://hackathon.ap4m.build";

/** x402 network identifier as AP4M reports it in a 402 challenge. */
export const X402_NETWORK = `eip155:${CHAIN_ID}`;

/**
 * The open x402 `exact` scheme (@x402/evm): one EIP-3009 transfer authorization per
 * payment.
 * Whether RLUSD on XRPL EVM implements EIP-3009 is NOT verified here; a merchant
 * states the token's EIP-712 domain in `extra.name` / `extra.version`.
 */
export const X402_SCHEME = "exact";

// Protocol versions, read from `@ap4m/sdk`'s own exported constants
// (`X402_VERSION = 2`, `X402_BINDING_VERSION = "1"`). Mirrored here so the pure
// modules need no dependency on the SDK.
export const X402_VERSION = 2;
export const X402_BINDING_VERSION = "1";

/** Headers AP4M uses for the x402 exchange. */
export const HEADERS = {
  required: "PAYMENT-REQUIRED",
  signature: "PAYMENT-SIGNATURE",
  response: "PAYMENT-RESPONSE",
  channelId: "X-AP4M-CHANNEL-ID",
};

/**
 * EIP-712 shape AP4M uses for a payment Voucher, for reference.
 * Note it carries no merchant, price or purpose — only a channel and a running
 * total — which is why a human cannot meaningfully review one, and why the
 * Mandate layer exists.
 */
export const VOUCHER_EIP712 = {
  domainName: "AP4M Payment Ledger",
  domainVersion: "1",
  types: {
    Voucher: [
      { name: "channelId", type: "bytes32" },
      { name: "cumulativeAmount", type: "uint256" },
    ],
  },
};

// Our own MandateRegistry (contracts/MandateRegistry.sol): on-chain revocation,
// and the EIP-712 `verifyingContract` for both Mandates and Revocations.
// Deployed 2026-10-25, tx 0xc9282ecc5288fd2406128827c573c4bb691ea1c74cefeb49b2d5af5f71a07d82
// (block 9229025). Its on-chain `revocationDigest` was checked against the
// locally computed EIP-712 digest at deploy time and agreed.
export const MANDATE_REGISTRY = "0x7B68a815682C0e7098D5cc604A18638077200a49";

export const REVOCATION_EIP712 = {
  domainName: "AgentSpendMandateRegistry",
  domainVersion: "1",
  types: {
    Revocation: [
      { name: "mandateId", type: "bytes32" },
      { name: "approver", type: "address" },
      { name: "nonce", type: "uint256" },
    ],
  },
};
