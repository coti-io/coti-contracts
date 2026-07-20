// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../IInbox.sol";

/// @dev Minimal inbox stand-in for {PrivacyPortalFactory.createPortal} unit tests; only implements the
///      one-way send used for mother token registration.
contract MockInbox {
    uint256 public lastTargetChainId;
    address public lastTargetContract;
    bytes public lastCallData;
    uint256 public sentCount;

    function sendOneWayMessage(
        uint256 targetChainId,
        address targetContract,
        IInbox.MpcMethodCall calldata methodCall,
        bytes4
    ) external payable returns (bytes32 requestId) {
        lastTargetChainId = targetChainId;
        lastTargetContract = targetContract;
        lastCallData = methodCall.data;
        sentCount += 1;
        requestId = keccak256(abi.encodePacked("registration", targetContract, sentCount));
    }
}
