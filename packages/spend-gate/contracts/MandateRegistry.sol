// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title MandateRegistry — on-chain revocation for agent spend mandates
/// @notice A human revokes a Mandate by signing a Revocation on their Ledger.
///         Anyone may then submit it. The device never needs gas, never needs
///         to be online, and the signature is the authority — exactly as it is
///         for the Mandate itself.
///
/// Three decisions worth stating, because each one is a security property:
///
/// 1. REVOCATION IS KEYED BY (approver, mandateId), not by mandateId alone.
///    The registry has no idea who "owns" a mandate — it never sees one — so a
///    global key would let anybody revoke anybody's mandate, or let a mandate
///    be censored by a stranger. A verifier asks only about the approver it
///    already trusts, so no one else's revocation can affect it, and no
///    registration step or admin is needed. There is no owner here at all.
///
/// 2. REVOCATION IS MONOTONIC AND HAS NO UNDO. There is no `unrevoke`. A
///    revocation is a safety brake, and a brake you can release remotely is a
///    brake an attacker can release. To resume spending, sign a new Mandate.
///
/// 3. NONCES ARE PER APPROVER AND SINGLE-USE, so a captured Revocation cannot
///    be replayed to revoke something else. Replay of the SAME revocation is
///    harmless (the state is already set) but it is rejected anyway, so a
///    relayer gets a clear error instead of paying gas for nothing.
contract MandateRegistry {
    /// @dev keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev keccak256("Revocation(bytes32 mandateId,address approver,uint256 nonce)")
    bytes32 private constant REVOCATION_TYPEHASH =
        keccak256("Revocation(bytes32 mandateId,address approver,uint256 nonce)");

    bytes32 private constant NAME_HASH = keccak256("AgentSpendMandateRegistry");
    bytes32 private constant VERSION_HASH = keccak256("1");

    /// @notice When `approver` revoked `mandateId`; 0 means not revoked.
    mapping(address => mapping(bytes32 => uint256)) public revokedAt;

    /// @notice Spent revocation nonces, per approver.
    mapping(address => mapping(uint256 => bool)) public nonceUsed;

    event Revoked(
        address indexed approver,
        bytes32 indexed mandateId,
        uint256 nonce,
        uint256 timestamp,
        address relayer
    );

    error BadSignature();
    error NonceAlreadyUsed();
    error AlreadyRevoked();

    /// @notice The EIP-712 domain separator for Revocations against this registry.
    function domainSeparator() public view returns (bytes32) {
        return
            keccak256(
                abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
            );
    }

    /// @notice The digest a device signs to revoke one mandate.
    function revocationDigest(
        bytes32 mandateId,
        address approver,
        uint256 nonce
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(REVOCATION_TYPEHASH, mandateId, approver, nonce)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Record a device-signed revocation. Callable by anyone.
    /// @dev The caller pays gas and gains nothing: it cannot alter who revoked
    ///      what, only whether a valid revocation gets recorded at all. That is
    ///      what makes relaying safe.
    function revoke(
        bytes32 mandateId,
        address approver,
        uint256 nonce,
        bytes calldata signature
    ) external {
        if (nonceUsed[approver][nonce]) revert NonceAlreadyUsed();
        if (revokedAt[approver][mandateId] != 0) revert AlreadyRevoked();
        if (_recover(revocationDigest(mandateId, approver, nonce), signature) != approver)
            revert BadSignature();

        nonceUsed[approver][nonce] = true;
        revokedAt[approver][mandateId] = block.timestamp;
        emit Revoked(approver, mandateId, nonce, block.timestamp, msg.sender);
    }

    /// @notice Has `approver` revoked `mandateId`?
    function isRevoked(address approver, bytes32 mandateId) external view returns (bool) {
        return revokedAt[approver][mandateId] != 0;
    }

    /// @notice Batch read, so a verifier checking several mandates makes one call.
    function areRevoked(
        address approver,
        bytes32[] calldata mandateIds
    ) external view returns (bool[] memory out) {
        out = new bool[](mandateIds.length);
        for (uint256 i = 0; i < mandateIds.length; i++) {
            out[i] = revokedAt[approver][mandateIds[i]] != 0;
        }
    }

    /// @dev ecrecover with the two checks ecrecover itself does not do:
    ///      canonical `s` (EIP-2, so one signature has one encoding) and a
    ///      non-zero result (ecrecover returns address(0) on failure, which
    ///      would otherwise compare equal to an address(0) approver).
    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert BadSignature();
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
            revert BadSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert BadSignature();
        return signer;
    }
}
