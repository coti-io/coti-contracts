// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../messaging/PrivateMessaging.sol";

contract PrivateMessagingHarness is PrivateMessaging {
    constructor(uint64 epochDurationSeconds) PrivateMessaging(epochDurationSeconds) {}

    function recordSyntheticMessage(
        address from,
        address to,
        ctString calldata networkCiphertext,
        ctString calldata senderCiphertext,
        ctString calldata recipientCiphertext
    ) external returns (uint256 messageId) {
        messageId = _createMessageRecord(from, to, 1);
        _addEpochUsage(currentEpoch(), from, networkCiphertext.value.length);
        _storeChunkCiphertexts(
            messageId,
            0,
            networkCiphertext,
            senderCiphertext,
            recipientCiphertext
        );
    }

    function recordSyntheticMultipartMessage(
        address from,
        address to,
        ctString[] calldata networkCiphertexts,
        ctString[] calldata senderCiphertexts,
        ctString[] calldata recipientCiphertexts
    ) external returns (uint256 messageId) {
        require(networkCiphertexts.length > 0, "chunk count");
        require(networkCiphertexts.length == senderCiphertexts.length, "sender length");
        require(networkCiphertexts.length == recipientCiphertexts.length, "recipient length");

        messageId = _createMessageRecord(from, to, networkCiphertexts.length);
        uint256 usageUnits;

        for (uint256 i = 0; i < networkCiphertexts.length; i++) {
            usageUnits += networkCiphertexts[i].value.length;
            _storeChunkCiphertexts(
                messageId,
                i,
                networkCiphertexts[i],
                senderCiphertexts[i],
                recipientCiphertexts[i]
            );
        }

        _addEpochUsage(currentEpoch(), from, usageUnits);
    }
}
