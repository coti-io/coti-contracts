// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../token/PrivateERC20/PrivateERC20.sol";
import "../../../utils/mpc/MpcCore.sol";

/**
 * @title PrivateERC20AuditorSupplyMock
 * @notice Example (audit issue #5, “option 3”): keep {totalSupply} privacy-preserving (returns 0 in the
 *         base contract) while a **designated auditor** obtains **aggregate supply re-encrypted** to their key.
 *         The default product stance for #5 “option 1” is **documentation only** — see {PrivateERC20} and
 *         {IPrivateERC20} NatSpec for `totalSupply` / {supplyCap}; this contract illustrates an optional extension.
 * @dev Flow:
 *      1. Deploy with `auditor` = EOA (or a contract that has called `setAccountEncryptionAddress`).
 *      2. Auditor calls `setAccountEncryptionAddress` if they use a dedicated off-chain key address.
 *      3. Auditor calls `totalSupplyCiphertextForAuditor()` and decrypts off-chain — not plaintext on-chain.
 *      For testing mints, grant `MINTER_ROLE` to a test account or use a deploy script; this mock does not add a public minter.
 */
contract PrivateERC20AuditorSupplyMock is PrivateERC20 {
    address public immutable auditor;

    error OnlyAuditor();
    error AuditorCannotReceiveUserCiphertext();

    constructor(address auditor_) PrivateERC20("PrivateERC20AuditorSupplyMock", "PAS") {
        if (auditor_ == address(0)) revert ERC20InvalidReceiver(address(0));
        auditor = auditor_;
    }

    /**
     * @notice Returns aggregate supply as ciphertext under the auditor’s encryption address (see {_getAccountEncryptionAddress}).
     * @dev Reverts if `msg.sender` is not `auditor`. Contract auditors without an AES key (`encryptionAddress == 0`) cannot use this path.
     */
    function totalSupplyCiphertextForAuditor() external nonReentrant returns (ctUint256 memory) {
        if (msg.sender != auditor) revert OnlyAuditor();

        address enc = _getAccountEncryptionAddress(auditor);
        if (enc == address(0)) revert AuditorCannotReceiveUserCiphertext();

        gtUint256 gtTotal = _getTotalSupplyGarbled();
        return MpcCore.offBoardToUser(gtTotal, enc);
    }
}
