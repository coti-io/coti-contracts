// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// @title IInbox
/// @notice Cross-chain request/response inbox: send messages to remote chains, execute incoming calls, and query state.
/// @dev Fee-related fields on {Request} are **gas unit** budgets, not wei. See {InboxFeeManager}.
interface IInbox {
    // --- Types ---

    /// @notice Classification of the current inbox execution when delivering an error callback.
    /// @dev Used by source `errorSelector` handlers: ignore {NotErrorContext}; branch on {SystemError} vs {Exception}.
    ///      Call only from `errorSelector` entrypoints — linked success `respond` legs can also report {Exception}.
    enum InboxErrorType {
        /// @notice No active message, or the active call is not a linked error/system delivery.
        NotErrorContext,
        /// @notice Inbox system-error return leg (`originalSender` is {SYSTEM_SENDER}).
        SystemError,
        /// @notice Linked return leg for a request that registered an `errorSelector` (app `raise`).
        Exception
    }

    /// @notice Minimal payload for Inbox system-error callbacks (`errorSelector(bytes data)`).
    /// @dev App `raise` payloads are dApp-defined; decode them only when {inboxErrorType()} is {Exception}.
    ///      System encode failure uses `errorCode = 2`. Attribution is via {SYSTEM_SENDER} on the return leg.
    struct ErrorData {
        uint64 errorCode;
        bytes message;
    }

    /// @notice Encoded method call and optional MPC ABI metadata.
    struct MpcMethodCall {
        /// @notice Function selector to re-encode with MPC GTs; zero means `data` is raw calldata.
        bytes4 selector;
        /// @notice ABI-encoded arguments or raw calldata.
        bytes data;
        /// @notice MPC datatype descriptors used by {MpcAbiCodec}.
        bytes8[] datatypes;
        /// @notice MPC ciphertext length descriptors used by {MpcAbiCodec}.
        bytes32[] datalens;
    }

    /// @notice Stored outbound or incoming cross-chain request.
    struct Request {
        /// @notice Packed request id containing source chain id and nonce.
        bytes32 requestId;
        /// @notice Destination chain id for outbound requests, or source chain id for incoming requests.
        uint256 targetChainId;
        /// @notice Contract invoked on the destination/current chain.
        address targetContract;
        /// @notice Method call executed on the target.
        MpcMethodCall methodCall;
        /// @notice Immediate caller that submitted the request.
        address callerContract;
        /// @notice Application contract that should receive responses/errors.
        address originalSender;
        /// @notice Request creation or ingestion timestamp.
        uint64 timestamp;
        /// @notice Callback selector used for two-way success responses.
        bytes4 callbackSelector;
        /// @notice Error selector invoked with `errorSelector(bytes data)` for app `raise` **or** Inbox system errors.
        /// @dev Same delivery path. Distinguish with {inboxErrorType()}: {SystemError} ({ErrorData} payload,
        ///      {SYSTEM_SENDER}) vs {Exception} (dApp-defined `raise` bytes). System errors are not eligible for
        ///      `retryFailedRequest`. Auth: `onlyInbox` + non-zero {inboxSourceRequestId}.
        bytes4 errorSelector;
        /// @notice True when a success response is expected.
        bool isTwoWay;
        /// @notice True after the inbox has processed this request (execution attempted) or, for an
        ///         original outbound two-way, after a linked return/error leg was *received*.
        /// @dev Does **not** mean the application callback committed. A return leg may still be in
        ///      `errors` / retryable if the callback reverted. See {IncomingResponseReceived}.
        bool executed;
        /// @dev If this request is a one-way response or error delivery, links to the original two-way request ID.
        bytes32 sourceRequestId;
        /// @dev Gas unit budget for the remote execution leg (`call{gas: ...}` cap). Not wei.
        uint256 targetFee;
        /// @dev Gas unit budget for the callback leg on the source chain. Not wei.
        uint256 callerFee;
    }

    /// @notice Response metadata for an incoming request.
    struct Response {
        /// @notice Outbound request id that delivered the response.
        bytes32 responseRequestId;
        /// @notice Response payload returned by the target contract.
        bytes response;
    }

    /// @notice Stored execution or encoding error for a request.
    struct Error {
        /// @notice Request id that failed.
        bytes32 requestId;
        /// @notice Protocol-defined error code.
        uint64 errorCode;
        /// @notice Revert data or encoded error message.
        bytes errorMessage;
    }

    /// @notice Active incoming execution context exposed to target contracts.
    struct ExecutionContext {
        /// @notice Remote chain that sent the current request.
        uint256 remoteChainId;
        /// @notice Remote contract that sent the current request.
        address remoteContract;
        /// @notice Current incoming request id.
        bytes32 requestId;
    }

    // --- External: sends (payable) ---

    /// @notice Send a two-way message with callback and error handlers on the remote chain.
    /// @param targetChainId Destination chain ID.
    /// @param targetContract Contract to call on the destination chain.
    /// @param methodCall Calldata and MPC metadata.
    /// @param callbackSelector Selector invoked on the source chain when the remote call succeeds.
    /// @param errorSelector Selector invoked on the source chain when the remote call fails.
    /// @param callbackFeeLocalWei Wei from `msg.value` reserved for the callback leg (converted to gas units in fee logic).
    /// @return requestId The new outbound request ID.
    function sendTwoWayMessage(
        uint256 targetChainId,
        address targetContract,
        MpcMethodCall calldata methodCall,
        bytes4 callbackSelector,
        bytes4 errorSelector,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32);

    /// @notice Send a one-way message with no callback and no error handler.
    /// @dev `errorSelector` must be zero. One-way messages do not generate raise/system-error return legs
    ///      (no funded `callerFee`). Use {sendTwoWayMessage} when the source needs an error callback.
    /// @param targetChainId Destination chain ID.
    /// @param targetContract Contract to call on the destination chain.
    /// @param methodCall Calldata and MPC metadata.
    /// @param errorSelector Must be `bytes4(0)`.
    /// @return requestId The new outbound request ID.
    function sendOneWayMessage(
        uint256 targetChainId,
        address targetContract,
        MpcMethodCall calldata methodCall,
        bytes4 errorSelector
    ) external payable returns (bytes32);

    /// @notice One-way sends cannot register an error callback (no funded return-leg budget).
    error OneWayErrorSelectorNotSupported(bytes4 errorSelector);

    // --- External: execution (non-payable) ---

    /// @notice Respond to the current incoming message (two-way flow).
    /// @dev Gas for the return leg is **not** charged again: it uses the `callerFee` budget from the original two-way request.
    /// @param data Payload routed to the original sender via `callbackSelector`.
    function respond(bytes memory data) external;

    /// @notice Signal an application error for the current incoming two-way message (same routing constraints as {respond}).
    /// @dev Gas for the return leg is **not** charged again: it uses the `callerFee` budget from the original two-way request.
    /// @param data ABI-encoded argument for the remote `errorSelector(bytes)`.
    function raise(bytes memory data) external;

    // --- External: views ---

    /// @notice Return error details for a failed outgoing / incoming request.
    /// @param requestId Request ID (outbound or mined incoming).
    /// @return code Error code (`1` = execution failed, `2` = encode failed).
    /// @return data Stored error bytes. For execution failures this is the first ≤256 bytes of
    ///         returndata (POD-02); decode `Error(string)` / custom errors in the client.
    function getOutboxError(bytes32 requestId) external view returns (uint256 code, bytes memory data);

    /// @notice Return stored response bytes for a completed incoming flow.
    /// @param requestId Incoming request ID.
    /// @return response Response payload.
    function getInboxResponse(bytes32 requestId) external view returns (bytes memory);

    /// @notice Return a slice of outbound requests sent to `targetChainId`, in per-target nonce order.
    /// @param targetChainId Destination chain whose outbound requests to read.
    /// @param from Start index (0-based) within that target's sequence.
    /// @param len Maximum number of requests to return.
    /// @return requestsList Request structs.
    function getRequests(uint256 targetChainId, uint256 from, uint256 len)
        external
        view
        returns (Request[] memory);

    /// @notice Total count of outbound requests issued from this inbox to `targetChainId`.
    /// @param targetChainId Destination chain.
    /// @return count Number of requests to that target.
    function getRequestsLen(uint256 targetChainId) external view returns (uint256);

    /// @notice Look up a stored outbound request by its id (id encodes source+target+nonce).
    /// @param requestId Outbound request id.
    /// @return request The stored request (zeroed if unknown).
    function getRequest(bytes32 requestId) external view returns (Request memory);

    /// @notice Look up a stored incoming request by its id (id encodes the source chain).
    /// @param requestId Incoming request id.
    /// @return request The stored incoming request (zeroed if unknown).
    function getIncomingRequest(bytes32 requestId) external view returns (Request memory);

    /// @notice Remote chain ID and contract for the currently executing incoming message.
    /// @dev For system-error return legs, `contractAddress` is {SYSTEM_SENDER}. Success callbacks still
    ///      come from the real remote peer; error callbacks should not require peer equality.
    /// @return chainId Remote chain ID.
    /// @return contractAddress Remote caller contract (or {SYSTEM_SENDER} for Inbox system errors).
    function inboxMsgSender() external view returns (uint256 chainId, address contractAddress);

    /// @notice Request ID for the currently executing incoming message.
    /// @return requestId Active request ID.
    function inboxRequestId() external view returns (bytes32);

    /// @notice Source request ID linked from the current incoming message (if any).
    /// @dev Non-zero only for reply/error legs created by {respond}, {raise}, or system-error delivery.
    ///      Public {sendOneWayMessage}/{sendTwoWayMessage} always use `sourceRequestId = 0`.
    /// @return sourceRequestId Linked request ID.
    function inboxSourceRequestId() external view returns (bytes32);

    /// @notice Whether the current execution is delivering a system error, an app `raise`, or neither.
    /// @dev Safe to call outside an active message (returns {InboxErrorType.NotErrorContext}). Prefer this over
    ///      requiring `inboxMsgSender()` peer equality in error handlers.
    /// @return errorType {InboxErrorType} for the active context.
    function inboxErrorType() external view returns (InboxErrorType errorType);

    // --- External: pure ---

    /// @notice Pack source chain id (64 bits), target chain id (64 bits) and nonce (128 bits) into a request id.
    /// @param sourceChainId Originating chain id.
    /// @param targetChainId Destination chain id.
    /// @param nonce Per-target nonce.
    /// @return requestId 256-bit packed id.
    function getRequestId(uint256 sourceChainId, uint256 targetChainId, uint256 nonce)
        external
        pure
        returns (bytes32);

    /// @notice Split a packed request id into source chain id, target chain id and nonce.
    /// @param requestId Packed id.
    /// @return sourceChainId Source chain id.
    /// @return targetChainId Target chain id.
    /// @return nonce Per-target nonce.
    function unpackRequestId(bytes32 requestId)
        external
        pure
        returns (uint256 sourceChainId, uint256 targetChainId, uint256 nonce);
}
