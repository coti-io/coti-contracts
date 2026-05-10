// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "./IInbox.sol";

/// @title IInboxMiner
/// @notice Miner API: apply mined cross-chain payloads to this chain's inbox and withdraw fees.
interface IInboxMiner {
    error RetryFailedRequestNotAFailedRequest();
    error RequestIdRequired();
    error RetryFailedRequestExecutionFailed(bytes returnData);

    /// @notice Emitted when {retryFailedRequest} successfully re-executes a previously failed incoming request.
    event RetryFailedRequestSuccess(bytes32 indexed requestId);

    /// @notice Mined inbound request. `targetFee` and `callerFee` are gas unit budgets (see {IInbox.Request}).
    struct MinedRequest {
        bytes32 requestId;
        address sourceContract;
        address targetContract;
        IInbox.MpcMethodCall methodCall;
        bytes4 callbackSelector;
        bytes4 errorSelector;
        bool isTwoWay;
        bytes32 sourceRequestId;
        uint256 targetFee;
        uint256 callerFee;
    }

    /// @notice Validate and execute a batch of mined requests from `sourceChainId`.
    /// @param sourceChainId Chain that produced the mined data.
    /// @param mined Ordered requests to apply.
    function batchProcessRequests(uint256 sourceChainId, MinedRequest[] memory mined) external;

    /// @notice Withdraw accumulated native token fees to `to` (owner-only in concrete implementations).
    function collectFees(address payable to) external;

    /// @notice Re-execute a mined incoming request whose target call failed (e.g. OOG). Open to any payer for gas.
    function retryFailedRequest(bytes32 requestId) external;
}
