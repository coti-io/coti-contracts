// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../InboxUser.sol";
import "../../fee/IInboxFeeManager.sol";
import "../../mpccodec/MpcAbiCodec.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./IPodERC20.sol";
import "./cotiside/IPodErc20CotiSide.sol";
import "../erc7984/PodErc7984Mixin.sol";

/// @title PodERC20
/// @notice PoD-side private ERC-20: ciphertext cache and inbox-mediated async moves; COTI holds authoritative garbled state via {IPodErc20CotiSide}.
/// @dev Callbacks only from `inbox` when the remote peer matches (`cotiChainId`, `cotiSideContract`). Public-amount methods expose amounts in calldata and logs; use encrypted `itUint256` entry points for privacy-sensitive flows.
contract PodERC20 is IPodERC20, InboxUser, PodErc7984Mixin {
    using MpcAbiCodec for MpcAbiCodec.MpcMethodCallContext;

    // --- State variables ---

    uint256 public cotiChainId;
    address public cotiSideContract;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    bool private _podERC20Initialized;
    /// @notice Nonces consumed by public transfer permits verified on PoD.
    mapping(address => uint256) public nonces;

    /// @dev Rough calldata size for the remote MPC method (itUint256 + two addresses or similar). Matches the test harness default.
    uint256 private constant FEE_ESTIMATE_REMOTE_CALL_SIZE = 512;
    /// @dev Rough calldata size for the PoD callback payload (`transferCallback`/`approveCallback`).
    uint256 private constant FEE_ESTIMATE_CALLBACK_CALL_SIZE = 512;
    /// @dev Headroom for COTI-side MPC execution (onBoard/sub/add/offBoard round-trip).
    uint256 private constant FEE_ESTIMATE_REMOTE_EXEC_GAS = 300_000;
    /// @dev Headroom for PoD callback execution (decode + storage writes).
    uint256 private constant FEE_ESTIMATE_CALLBACK_EXEC_GAS = 300_000;
    bytes32 private constant PUBLIC_TRANSFER_PERMIT_TYPEHASH =
        keccak256("TransferPermit(address owner,address spender,address to,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant PERMIT_DOMAIN_VERSION_HASH = keccak256("1");
    mapping(address => ctUint256) private _balances;
    mapping(address => mapping(address => IPodERC20.Allowance)) private _allowance;
    /// @dev One in-flight transfer or burn per address (used as both sender and receiver lock for transfers).
    mapping(address => bytes32) private _pendingTransferRequestIds;
    mapping(address => mapping(address => bytes32)) private _pendingApprovalRequestIds;
    /// @dev Optional `transferAndCall` payload keyed by inbox `sourceRequestId`, cleared after callback.
    mapping(bytes32 => bytes) private _requestCallbacks;
    mapping(bytes32 => IPodERC20.RequestStatus) public requests;
    mapping(bytes32 => bytes) public failedRequests;
    /// @dev Monotonic nonce from COTI; stale callbacks do not overwrite newer balances.
    mapping(address => uint256) public balanceNonces;

    // --- Events (PoD-specific; {Transfer}, {Approval}, etc. are declared on {IPodERC20}) ---

    /// @notice Async transfer request was submitted to COTI.
    event TransferRequestSubmitted(address indexed from, address indexed to, bytes32 requestId);
    /// @notice Async approval request was submitted to COTI.
    event ApprovalRequestSubmitted(address indexed owner, address indexed spender, bytes32 requestId);
    /// @notice Async approval request failed on COTI.
    event ApprovalFailed(address indexed owner, address indexed spender, bytes errorMsg);
    /// @notice Async balance-sync request failed on COTI.
    event SyncBalancesFailed(bytes32 requestId, bytes errorMsg);
    /// @notice Async balance-sync request was submitted for accounts.
    event SyncBalancesRequested(address[] accounts, bytes32 requestId);

    // --- Errors ---

    /// @notice A transfer/burn lock already exists for one of the affected accounts.
    error TransferAlreadyPending(address from, address to, bytes32 requestId);
    /// @notice An approval lock already exists for the owner/spender pair.
    error ApprovalAlreadyPending(address owner, address spender, bytes32 requestId);
    /// @notice Inbox caller was not the configured COTI-side peer.
    error OnlyCotiSideContract(uint256 remoteChainId, address remoteContract);
    /// @notice Thrown by the default {_checkMinter} hook; subclasses (e.g. {PodErc20Mintable}) can override to allow minting.
    error MintNotAllowed(address caller);
    /// @notice Clone storage was already initialized.
    error PodERC20AlreadyInitialized();
    /// @notice Initializer received an invalid zero address or chain id.
    error PodERC20InvalidInitialization();
    /// @notice Public transfer permit deadline has passed.
    error PermitExpired(uint256 deadline);
    /// @notice Public transfer permit signer did not match the owner.
    error InvalidPermitSigner(address signer, address owner);

    // --- Constructor ---

    /**
     * @param _cotiChainId Chain id of COTI; must match {IInbox.inboxMsgSender} when the peer calls back.
     * @param _inbox Cross-chain inbox used for two-way messages (also sets {InboxUser.inbox}).
     * @param _cotiSideContract Deployed {IPodErc20CotiSide} this token talks to on COTI.
     * @param _name ERC-20 name string (public metadata on PoD).
     * @param _symbol ERC-20 symbol string (public metadata on PoD).
     */
    constructor(
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol
    ) {
        _initializePodERC20(_cotiChainId, _inbox, _cotiSideContract, _name, _symbol);
    }

    /// @notice Accept native funds used to pay inbox fees for async pToken operations.
    /// @dev `_sendPodTwoWay` may spend existing contract balance, so operational tooling can pre-fund this token for auto-fee flows.
    receive() external payable {}

    // --- External: mutating (user / admin) ---

    /**
     * @inheritdoc IPodERC20
     * @dev **Gotcha:** reverts if either party already has a pending transfer. **Gotcha:** `TransferRequestSubmitted` indexes
     *      `msg.sender` as `from`, not the `from` argument of internal `_transfer` (same for direct `transfer`).
     */
    function transfer(address to, itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _transfer(IPodErc20CotiSide.transfer.selector, msg.sender, to, value, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function transfer(address to, itUint256 calldata value) external payable returns (bytes32 requestId) {
        (, uint256 callbackFeeLocalWei) = _estimateTwoWayFeeInLocalToken();
        return _transfer(IPodErc20CotiSide.transfer.selector, msg.sender, to, value, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function transferFrom(address from, address to, itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _transferFrom(IPodErc20CotiSide.transferFromAsSpender.selector, msg.sender, from, to, value, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function transferFrom(address from, address to, itUint256 calldata value) external payable returns (bytes32 requestId) {
        (, uint256 callbackFeeLocalWei) = _estimateTwoWayFeeInLocalToken();
        return _transferFrom(IPodErc20CotiSide.transferFromAsSpender.selector, msg.sender, from, to, value, msg.value, callbackFeeLocalWei);
    }

    /**
     * @inheritdoc IPodERC20
     * @dev Stores `data` under the new `requestId` until {transferCallback} runs successfully and forwards it to `to`.
     */
    function transferAndCall(
        address to,
        itUint256 calldata amount,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId) {
        requestId = _transfer(IPodErc20CotiSide.transfer.selector, msg.sender, to, amount, msg.value, callbackFeeLocalWei);
        _requestCallbacks[requestId] = data;
        return requestId;
    }

    /// @inheritdoc IPodERC20
    function transferFromAndCall(
        address from,
        address to,
        uint256 amount,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId) {
        requestId = _transferPublicFrom(
            IPodErc20CotiSide.transferFromPublicAsSpender.selector,
            msg.sender,
            from,
            to,
            amount,
            msg.value,
            callbackFeeLocalWei
        );
        _requestCallbacks[requestId] = data;
    }

    /// @inheritdoc IPodERC20
    function transferFromAndCallWithPermit(
        address from,
        address to,
        uint256 amount,
        PublicPermit calldata permit,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId) {
        requestId = _transferPublicFromWithPermit(
            msg.sender,
            from,
            to,
            amount,
            permit,
            msg.value,
            callbackFeeLocalWei
        );
        _requestCallbacks[requestId] = data;
    }

    /// @inheritdoc IPodERC20
    function approve(address spender, itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _approve(msg.sender, spender, value, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function approve(address spender, itUint256 calldata value) external payable returns (bytes32 requestId) {
        (, uint256 callbackFeeLocalWei) = _estimateTwoWayFeeInLocalToken();
        return _approve(msg.sender, spender, value, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function burn(itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _burn(msg.sender, value, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function mint(address to, itUint256 calldata amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        _checkMinter();
        return _mint(to, amount, msg.value, callbackFeeLocalWei);
    }

    // --- External: mutating (plain uint256 variants) ---

    /// @inheritdoc IPodERC20
    function transfer(address to, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _transferPublic(IPodErc20CotiSide.transferPublic.selector, msg.sender, to, amount, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function transferFrom(address from, address to, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _transferPublicFrom(IPodErc20CotiSide.transferFromPublicAsSpender.selector, msg.sender, from, to, amount, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function approve(address spender, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _approvePublic(msg.sender, spender, amount, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function burn(uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _burnPublic(msg.sender, amount, msg.value, callbackFeeLocalWei);
    }

    /// @inheritdoc IPodERC20
    function mint(address to, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        _checkMinter();
        return _mintPublic(to, amount, msg.value, callbackFeeLocalWei);
    }

    /**
     * @inheritdoc IPodERC20
     * @dev Does not record a “pending” flag per account for sync; only transfers/burns use the pending-transfer map.
     */
    function syncBalances(address[] calldata accounts, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.syncBalances.selector, 1)
            .addArgument(accounts)
            .build();

        requestId = _sendPodTwoWay(
            msg.value,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.syncBalancesCallback.selector,
            PodERC20.syncBalancesError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        emit SyncBalancesRequested(accounts, requestId);
    }

    // --- External: inbox callbacks (success) ---

    /**
     * @notice Applies post-transfer ciphertext balances and optional `transferAndCall` hook.
     * @dev **Gotcha:** balance updates apply only when `nonce` exceeds {balanceNonces}; replays with old nonces are ignored.
     *      COTI {PodErc20CotiMother} starts per-token callback nonces at 1 on registration so the first update applies.
     *      **Gotcha:** `to.call(callbackData)` uses all remaining gas; failures emit {RequestCallbackFailed} only.
     */
    function transferCallback(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
        bytes32 sourceRequestId = inbox.inboxSourceRequestId();
        _setRequestStatus(sourceRequestId, IPodERC20.RequestStatus.Success);
        (
            address from,
            ctUint256 memory newBalanceFrom,
            ctUint256 memory senderValue,
            address to,
            ctUint256 memory newBalanceTo,
            ctUint256 memory receiverValue,
            uint256 nonce
        ) = abi.decode(data, (address, ctUint256, ctUint256, address, ctUint256, ctUint256, uint256));
        if (from != address(0)) {
            _pendingTransferRequestIds[from] = bytes32(0);
            if (balanceNonces[from] < nonce) {
                _balances[from] = newBalanceFrom;
                balanceNonces[from] = nonce;
            }
        }
        if (to != address(0)) {
            _pendingTransferRequestIds[to] = bytes32(0);
            if (balanceNonces[to] < nonce) {
                _balances[to] = newBalanceTo;
                balanceNonces[to] = nonce;
            }
        }
        bytes memory callbackData = _requestCallbacks[sourceRequestId];
        emit Transfer(from, to, senderValue, receiverValue);
        _emitConfidentialTransfer(from, to, senderValue, receiverValue);
        if (callbackData.length != 0) {
            (bool success, ) = address(to).call(callbackData);
            if (success) {
                delete _requestCallbacks[sourceRequestId];
            } else {
                emit RequestCallbackFailed(from, to, sourceRequestId, callbackData);
            }
        }
    }

    /**
     * @notice Writes new allowance ciphertext after COTI approved the request.
     * @dev Clears the pending approval slot for `(owner, spender)`.
     */
    function approveCallback(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
        bytes32 sourceRequestId = inbox.inboxSourceRequestId();
        _setRequestStatus(sourceRequestId, IPodERC20.RequestStatus.Success);
        (address owner, ctUint256 memory ownerAmount, address spender, ctUint256 memory spenderAmount) = abi.decode(
            data,
            (address, ctUint256, address, ctUint256)
        );
        _pendingApprovalRequestIds[owner][spender] = bytes32(0);
        _allowance[owner][spender] = Allowance({spenderCiphertext: spenderAmount, ownerCiphertext: ownerAmount});
        emit Approval(owner, spender, ownerAmount, spenderAmount);
    }

    /**
     * @notice Applies batched balance ciphertexts from COTI after `syncBalances`.
     * @dev Per-account update only if `nonce` is newer than {balanceNonces}; emits {BalanceSynced} for each update applied.
     *      COTI callback nonces start at 1 when the pToken namespace is registered on the mother.
     */
    function syncBalancesCallback(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
        bytes32 sourceRequestId = inbox.inboxSourceRequestId();
        _setRequestStatus(sourceRequestId, IPodERC20.RequestStatus.Success);
        (address[] memory addresses, ctUint256[] memory amounts, uint256 nonce) = abi.decode(
            data,
            (address[], ctUint256[], uint256)
        );
        for (uint256 i = 0; i < addresses.length; i++) {
            if (balanceNonces[addresses[i]] < nonce) {
                _balances[addresses[i]] = amounts[i];
                balanceNonces[addresses[i]] = nonce;
                emit BalanceSynced(addresses[i], amounts[i]);
            }
        }
    }

    // --- External: inbox callbacks (errors) ---

    /**
     * @notice Clears pending transfer state and records `failedRequests` for this `sourceRequestId`.
     * @dev **Gotcha:** when both `from` and `to` were locked, both are cleared; `TransferFailed` carries decoded addresses.
     */
    function transferError(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
        (address from, address to, bytes memory errorMsg) = abi.decode(data, (address, address, bytes));
        bytes32 sourceRequestId = inbox.inboxSourceRequestId();
        _setRequestStatus(sourceRequestId, IPodERC20.RequestStatus.Failed);
        failedRequests[sourceRequestId] = errorMsg;
        if (from != address(0)) {
            _pendingTransferRequestIds[from] = bytes32(0);
        }
        _pendingTransferRequestIds[to] = bytes32(0);
        emit TransferFailed(from, to, errorMsg);
    }

    /// @notice Clears pending approval and surfaces COTI error bytes to listeners and {failedRequests}.
    function approveError(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
        (address owner, address spender, bytes memory errorMsg) = abi.decode(data, (address, address, bytes));
        bytes32 sourceRequestId = inbox.inboxSourceRequestId();
        _setRequestStatus(sourceRequestId, IPodERC20.RequestStatus.Failed);
        failedRequests[sourceRequestId] = errorMsg;
        _pendingApprovalRequestIds[owner][spender] = bytes32(0);
        emit ApprovalFailed(owner, spender, errorMsg);
    }

    /// @notice `syncBalances` failed on COTI; `data` is forwarded into {SyncBalancesFailed} for debugging.
    function syncBalancesError(bytes memory data) external onlyInbox {
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != cotiSideContract) {
            revert OnlyCotiSideContract(remoteChainId, remoteContract);
        }
        bytes32 sourceRequestId = inbox.inboxSourceRequestId();
        _setRequestStatus(sourceRequestId, IPodERC20.RequestStatus.Failed);
        emit SyncBalancesFailed(sourceRequestId, data);
    }

    // --- External: views ---

    /// @inheritdoc IPodERC20
    function balanceOf(address account) external view returns (ctUint256 memory) {
        return _balances[account];
    }

    /// @inheritdoc IPodERC20
    function balanceOfWithStatus(address account) external view returns (ctUint256 memory, bool pending) {
        return (_balances[account], _pendingTransferRequestIds[account] != bytes32(0));
    }

    /// @inheritdoc IPodERC20
    function allowance(address owner, address spender) external view returns (Allowance memory) {
        return _allowance[owner][spender];
    }

    /// @inheritdoc IPodERC20
    function allowanceWithStatus(
        address owner,
        address spender
    ) external view returns (Allowance memory, bool pending) {
        return (_allowance[owner][spender], _pendingApprovalRequestIds[owner][spender] != bytes32(0));
    }

    /**
     * @notice Estimate the native fee split used by auto-fee two-way token methods.
     * @return totalFeeWei Sum of target and callback fee estimates.
     * @return targetFeeWei Estimated local-token wei for the remote COTI execution leg.
     * @return callbackFeeWei Estimated local-token wei for the PoD callback leg.
     */
    function estimateFee()
        external
        view
        returns (uint256 totalFeeWei, uint256 targetFeeWei, uint256 callbackFeeWei)
    {
        (targetFeeWei, callbackFeeWei) = _estimateTwoWayFeeInLocalToken();
        totalFeeWei = targetFeeWei + callbackFeeWei;
    }

    /// @notice EIP-712 domain separator used by {transferFromAndCallWithPermit}.
    function publicTransferPermitDomainSeparator() external view returns (bytes32) {
        return _publicTransferPermitDomainSeparator();
    }

    // --- Internal ---

    function _initializePodERC20(
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol
    ) internal {
        _initializePodERC20(_cotiChainId, _inbox, _cotiSideContract, _name, _symbol, 18);
    }

    function _initializePodERC20(
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) internal {
        if (_podERC20Initialized) {
            revert PodERC20AlreadyInitialized();
        }
        if (_cotiChainId == 0 || _inbox == address(0) || _cotiSideContract == address(0)) {
            revert PodERC20InvalidInitialization();
        }
        _podERC20Initialized = true;
        setInbox(_inbox);
        cotiChainId = _cotiChainId;
        cotiSideContract = _cotiSideContract;
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = 0;
    }

    /**
     * @notice Access-control hook invoked by {mint} overloads; base implementation always reverts with {MintNotAllowed}.
     * @dev Override in subclasses (e.g. {PodErc20Mintable}) to whitelist callers. The `msg.sender != address(0)` guard
     *      is always true at runtime but hides the unconditional revert from the compiler so callers don't trip the
     *      "unreachable code" warning in the base contract.
     */
    function _checkMinter() internal view virtual {
        if (msg.sender != address(0)) {
            revert MintNotAllowed(msg.sender);
        }
    }

    /// @param totalValueWei Total native payment (e.g. `msg.value`); `callbackFeeLocalWei` is the caller-supplied callback slice.
    function _sendPodTwoWay(
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei,
        IInbox.MpcMethodCall memory mpcMethodCall,
        bytes4 callbackSelector_,
        bytes4 errorSelector_
    ) internal returns (bytes32) {
        require(callbackFeeLocalWei >= 1, "PodERC20: callback fee min");
        require(callbackFeeLocalWei <= totalValueWei, "PodERC20: callback exceeds total");
        require(address(this).balance >= totalValueWei, "PodERC20: inbox fee");
        return IInbox(inbox).sendTwoWayMessage{value: totalValueWei}(
            cotiChainId,
            cotiSideContract,
            mpcMethodCall,
            callbackSelector_,
            errorSelector_,
            callbackFeeLocalWei
        );
    }

    function _setRequestStatus(bytes32 requestId, IPodERC20.RequestStatus status) internal {
        requests[requestId] = status;
        emit RequestStatusUpdated(requestId, status);
    }

    function _approve(address owner, address spender, itUint256 calldata value, uint256 totalValueWei, uint256 callbackFeeLocalWei) internal returns (bytes32 requestId) {
        if (_pendingApprovalRequestIds[owner][spender] != bytes32(0)) {
            revert ApprovalAlreadyPending(owner, spender, _pendingApprovalRequestIds[owner][spender]);
        }
        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.approve.selector, 3)
            .addArgument(owner)
            .addArgument(spender)
            .addArgument(value)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.approveCallback.selector,
            PodERC20.approveError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingApprovalRequestIds[owner][spender] = requestId;
        emit ApprovalRequestSubmitted(owner, spender, requestId);
    }

    function _burn(address from, itUint256 calldata value, uint256 totalValueWei, uint256 callbackFeeLocalWei) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0)) {
            revert TransferAlreadyPending(from, address(0), _pendingTransferRequestIds[from]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.burn.selector, 2)
            .addArgument(from)
            .addArgument(value)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );

        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        emit TransferRequestSubmitted(from, address(0), requestId);
    }

    /**
     * @dev **Gotcha:** `TransferAlreadyPending` carries `_pendingTransferRequestIds[from]` even when `to` was the party that
     *      was actually pending—inspect both sides off-chain when debugging reverts.
     */
    function _transfer(
        bytes4 remoteTransferSelector,
        address from,
        address to,
        itUint256 calldata value,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0) || _pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(from, to, _pendingTransferRequestIds[from]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(remoteTransferSelector, 3)
            .addArgument(from)
            .addArgument(to)
            .addArgument(value)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(msg.sender, to, requestId);
    }

    function _transferFrom(
        bytes4 remoteTransferSelector,
        address spender,
        address from,
        address to,
        itUint256 calldata value,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0) || _pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(from, to, _pendingTransferRequestIds[from]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(remoteTransferSelector, 4)
            .addArgument(spender)
            .addArgument(from)
            .addArgument(to)
            .addArgument(value)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(from, to, requestId);
    }

    /**
     * @notice Shared two-way-fee estimator used by the auto-fee overloads.
     * @dev Uses {InboxFeeManager.calculateTwoWayFeeRequiredInLocalToken} with heuristic calldata/execution sizes.
     *      Amounts returned are in local (PoD) wei; the caller must send `msg.value >= targetFeeWei + callbackFeeWei`.
     */
    function _estimateTwoWayFeeInLocalToken()
        internal
        view
        returns (uint256 targetFeeWei, uint256 callbackFeeWei)
    {
        (targetFeeWei, callbackFeeWei) = IInboxFeeManager(address(inbox)).calculateTwoWayFeeRequiredInLocalToken(
            FEE_ESTIMATE_REMOTE_CALL_SIZE,
            FEE_ESTIMATE_CALLBACK_CALL_SIZE,
            FEE_ESTIMATE_REMOTE_EXEC_GAS,
            FEE_ESTIMATE_CALLBACK_EXEC_GAS,
            tx.gasprice
        );
    }

    function _consumePublicTransferPermit(
        address owner,
        address spender,
        address to,
        uint256 amount,
        PublicPermit calldata permit
    ) internal {
        if (block.timestamp > permit.deadline) {
            revert PermitExpired(permit.deadline);
        }

        uint256 nonce = nonces[owner];
        bytes32 structHash = keccak256(
            abi.encode(PUBLIC_TRANSFER_PERMIT_TYPEHASH, owner, spender, to, amount, nonce, permit.deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _publicTransferPermitDomainSeparator(), structHash));
        address signer = ECDSA.recover(digest, permit.v, permit.r, permit.s);
        if (signer != owner) {
            revert InvalidPermitSigner(signer, owner);
        }
        nonces[owner] = nonce + 1;
    }

    function _publicTransferPermitDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                PERMIT_DOMAIN_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev Encrypted mint: sends `(to, amount)` to COTI's {IPodErc20CotiSide.mint} and locks `to`'s pending slot.
    function _mint(
        address to,
        itUint256 calldata amount,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(address(0), to, _pendingTransferRequestIds[to]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.mint.selector, 2)
            .addArgument(to)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(address(0), to, requestId);
    }

    /// @dev Plain-uint256 transfer / transferFrom; sends to `IPodErc20CotiSide.transferPublic` / `transferFromPublic`.
    function _transferPublic(
        bytes4 remoteSelector,
        address from,
        address to,
        uint256 amount,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0) || _pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(from, to, _pendingTransferRequestIds[from]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(remoteSelector, 3)
            .addArgument(from)
            .addArgument(to)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(msg.sender, to, requestId);
    }

    function _transferPublicFrom(
        bytes4 remoteSelector,
        address spender,
        address from,
        address to,
        uint256 amount,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0) || _pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(from, to, _pendingTransferRequestIds[from]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(remoteSelector, 4)
            .addArgument(spender)
            .addArgument(from)
            .addArgument(to)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(from, to, requestId);
    }

    function _transferPublicFromWithPermit(
        address spender,
        address from,
        address to,
        uint256 amount,
        PublicPermit calldata permit,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0) || _pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(from, to, _pendingTransferRequestIds[from]);
        }
        _consumePublicTransferPermit(from, spender, to, amount, permit);

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.transferFromPublic.selector, 3)
            .addArgument(from)
            .addArgument(to)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(from, to, requestId);
    }

    /// @dev Plain-uint256 approve; sends to `IPodErc20CotiSide.approvePublic`.
    function _approvePublic(
        address owner,
        address spender,
        uint256 amount,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingApprovalRequestIds[owner][spender] != bytes32(0)) {
            revert ApprovalAlreadyPending(owner, spender, _pendingApprovalRequestIds[owner][spender]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.approvePublic.selector, 3)
            .addArgument(owner)
            .addArgument(spender)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.approveCallback.selector,
            PodERC20.approveError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingApprovalRequestIds[owner][spender] = requestId;
        emit ApprovalRequestSubmitted(owner, spender, requestId);
    }

    /// @dev Plain-uint256 burn; sends to `IPodErc20CotiSide.burnPublic`.
    function _burnPublic(
        address from,
        uint256 amount,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[from] != bytes32(0)) {
            revert TransferAlreadyPending(from, address(0), _pendingTransferRequestIds[from]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.burnPublic.selector, 2)
            .addArgument(from)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[from] = requestId;
        emit TransferRequestSubmitted(from, address(0), requestId);
    }

    /// @dev Plain-uint256 mint; sends to `IPodErc20CotiSide.mintPublic`.
    function _mintPublic(
        address to,
        uint256 amount,
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei
    ) internal returns (bytes32 requestId) {
        if (_pendingTransferRequestIds[to] != bytes32(0)) {
            revert TransferAlreadyPending(address(0), to, _pendingTransferRequestIds[to]);
        }

        IInbox.MpcMethodCall memory mpcMethodCall = MpcAbiCodec.create(IPodErc20CotiSide.mintPublic.selector, 2)
            .addArgument(to)
            .addArgument(amount)
            .build();

        requestId = _sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            PodERC20.transferCallback.selector,
            PodERC20.transferError.selector
        );
        _setRequestStatus(requestId, IPodERC20.RequestStatus.Pending);
        _pendingTransferRequestIds[to] = requestId;
        emit TransferRequestSubmitted(address(0), to, requestId);
    }

    // --- ERC-7984 mixin hooks ---

    function _erc7984BalanceOf(address account) internal view override returns (ctUint256 memory) {
        return _balances[account];
    }
}
