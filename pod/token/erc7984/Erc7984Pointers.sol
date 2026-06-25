// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/// @title Erc7984Pointers
/// @notice Maps PoD ciphertext views to ERC-7984 `bytes32` confidential pointers for explorers.
library Erc7984Pointers {
    /// @dev Deterministic handle from dual-limb PoD balance/transfer ciphertext. Does not reveal plaintext.
    function toHandle(ctUint256 memory ct) internal pure returns (bytes32) {
        return keccak256(abi.encode(ct.ciphertextHigh, ct.ciphertextLow));
    }

    /// @dev Pick the party-specific amount view for a completed transfer/mint/burn callback.
    function transferAmountHandle(
        address from,
        address to,
        ctUint256 memory senderValue,
        ctUint256 memory receiverValue
    ) internal pure returns (bytes32) {
        if (from == address(0)) {
            return toHandle(receiverValue);
        }
        if (to == address(0)) {
            return toHandle(senderValue);
        }
        return toHandle(receiverValue);
    }
}
