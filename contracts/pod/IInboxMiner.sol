// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./IInbox.sol";

/// @title IInboxMiner
/// @notice Miner API: apply mined cross-chain payloads to this chain's inbox and withdraw fees.
interface IInboxMiner {
    error RetryFailedRequestNotAFailedRequest();
    error RequestIdRequired();
    error RetryFailedRequestExecutionFailed(bytes returnData);
    /// @notice Encode failed during retry; original execution error is preserved for a later retry.
    error RetryFailedRequestEncodeFailed(bytes encodeError);
    /// @notice The `sourceChainId` passed to {batchProcessRequests} is this chain's own id.
    error SourceChainIsThisChain(uint256 chainId);
    /// @notice A mined request's encoded source chain does not match the batch `sourceChainId`.
    error RequestSourceChainMismatch(bytes32 requestId, uint256 expectedSourceChainId, uint256 actualSourceChainId);
    /// @notice A mined request's encoded target chain is not this chain.
    error RequestTargetChainMismatch(bytes32 requestId, uint256 expectedTargetChainId, uint256 actualTargetChainId);
    /// @notice Inbound message processing is paused (circuit breaker).
    error MessageProcessingPaused();

    /// @notice Emitted when {retryFailedRequest} successfully re-executes a previously failed incoming request.
    event RetryFailedRequestSuccess(bytes32 indexed requestId);
    /// @notice Emitted when the owner toggles the message-processing circuit breaker.
    event MessageProcessingPausedUpdated(bool paused);
    /// @notice Miner rejected an inbound nonce in-batch (no fat payload stored).
    /// @dev `rejectionCode` / `rejectionReason` come from the special reject {IInbox.MpcMethodCall}.
    event RequestRejected(bytes32 indexed requestId, uint8 rejectionCode, bytes32 rejectionReason);

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

    /// @notice Pause or unpause inbound message processing (owner-only circuit breaker).
    function setMessageProcessingPaused(bool paused) external;

    /// @notice Re-execute a mined incoming request whose target call failed (e.g. OOG). Open to any payer for gas.
    function retryFailedRequest(bytes32 requestId) external;

    /// @notice Build the special {IInbox.MpcMethodCall} that marks an in-batch miner reject (no fat payload).
    /// @dev Pass as {MinedRequest.methodCall} with the real header fields unchanged.
    function buildMinerRejectMethodCall(uint8 rejectionCode, bytes32 rejectionReason)
        external
        pure
        returns (IInbox.MpcMethodCall memory methodCall);

    /// @notice Whether `methodCall` is the special in-batch reject encoding.
    function isMinerRejectMethodCall(IInbox.MpcMethodCall memory methodCall)
        external
        pure
        returns (bool isReject, uint8 rejectionCode, bytes32 rejectionReason);

    /// @notice Always-revert estimate of user execution gas and reply outbound sizes.
    /// @dev Intended for `eth_call`. Public. Nested call uses `maxUserGas` (and prepaid targetFee budget).
    ///      Reverts with {ExecutionGasEstimate}. `responseDataSize > 0` means `respond()` ran;
    ///      `errorDataSize > 0` means `raise()` / system-error outbound.
    error ExecutionGasEstimate(uint256 gasUsed, uint256 responseDataSize, uint256 errorDataSize);
    /// @notice Estimate called while another estimate or active execution context is live.
    error EstimateBusy();
    /// @notice Reject-sentinel methodCall cannot be estimated (nothing to execute).
    error EstimateRejectNotExecutable();

    /// @notice Simulate execute for `mined` under `maxUserGas`. Always reverts with {ExecutionGasEstimate}.
    function estimateExecutionGasForMiner(
        uint256 sourceChainId,
        MinedRequest calldata mined,
        uint256 maxUserGas
    ) external;
}
