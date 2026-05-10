// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "@coti-io/coti-contracts/contracts/utils/mpc/MpcCore.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "../../../InboxUser.sol";
import "./IPodErc20CotiSide.sol";

/// @title PodErc20CotiSide
/// @notice COTI-side ledger for {PodERC20}: `ctUint256` balances/allowances; garbled `gtUint256` only in memory around MPC ops.
/// @dev Entry points are inbox-only for the configured remote chain and contract. Owner must {setAuthorizedRemote} after deploy.
contract PodErc20CotiSide is IPodErc20CotiSide, InboxUser, Ownable {
    // --- State variables ---

    /// @notice Chain ID where the trusted `PodERC20` lives (must match {IInbox.inboxMsgSender}’s chain).
    uint256 public authorizedRemoteChainId;
    /// @notice Address of that `PodERC20` on the remote chain.
    address public authorizedRemoteContract;
    /// @notice Increments on successful state-changing MPC paths; included in PoD callbacks for ordering.
    uint256 public nonce;
    /// @dev Balance ciphertext per account (`offBoard` of garbled balance), same design as {PErc20Coti}.
    mapping(address => ctUint256) private _balanceCiphertext;
    /// @dev Allowance ciphertext: `owner => spender => ctUint256`.
    mapping(address => mapping(address => ctUint256)) private _allowanceCiphertext;
    bool private _cotiSideInitialized;

    // --- Events ---

    /// @notice Trusted source-chain pToken peer was updated.
    event AuthorizedRemoteUpdated(uint256 indexed chainId, address indexed remoteContract);
    /// @notice Clone or constructor initialization completed.
    event CotiSideInitialized(address indexed inbox, address indexed owner);
    /// @notice Owner minted public amount into a COTI-side balance.
    event OwnerMinted(address indexed to, uint256 amount, uint256 newNonce);
    /// @notice Balance ciphertexts were returned to the PoD side.
    event SyncBalancesResponded(address[] accounts, uint256 nonce);
    /// @notice Transfer path completed; `publicAmount` is populated only for public-amount flows.
    event TransferCompleted(
        address indexed spender,
        address indexed from,
        address indexed to,
        bool allowanceSpent,
        bool amountIsPublic,
        uint256 publicAmount,
        uint256 nonce
    );
    /// @notice Burn path completed; `publicAmount` is populated only for public-amount flows.
    event BurnCompleted(address indexed from, bool amountIsPublic, uint256 publicAmount, uint256 nonce);
    /// @notice Mint path completed; `publicAmount` is populated only for public-amount flows.
    event MintCompleted(address indexed to, bool amountIsPublic, uint256 publicAmount, uint256 nonce);
    /// @notice Approval path completed; `publicAmount` is populated only for public-amount flows.
    event ApprovalCompleted(address indexed owner, address indexed spender, bool amountIsPublic, uint256 publicAmount);
    /// @notice Transfer failure was reported back to the PoD side.
    event TransferFailureRaised(address indexed from, address indexed to, bytes reason);
    /// @notice Approval failure was reported back to the PoD side.
    event ApprovalFailureRaised(address indexed owner, address indexed spender, bytes reason);
    /// @notice Balance-sync failure was reported back to the PoD side.
    event SyncBalancesFailureRaised(bytes reason);

    // --- Errors ---

    /// @notice Authorized PoD-side peer has not been configured.
    error TrustedRemoteNotConfigured();
    /// @notice Authorized PoD-side peer chain or contract is zero.
    error InvalidAuthorizedRemotePeer();
    /// @notice Active inbox message did not originate from the authorized peer.
    error UntrustedRemoteCaller(uint256 chainId, address remoteContract);
    /// @notice Owner mint recipient was zero.
    error MintToZeroAddress();
    /// @notice Clone storage was already initialized.
    error PodErc20CotiSideAlreadyInitialized();
    /// @notice Initializer received an invalid inbox or owner address.
    error PodErc20CotiSideInvalidInitialization();

    // --- Modifiers ---

    /// @dev Caller must be the inbox, and the active cross-chain message must be from the authorized `PodERC20`.
    modifier onlyAuthorizedPodTokenMessage() {
        if (msg.sender != address(inbox)) {
            revert OnlyInbox(msg.sender);
        }
        if (authorizedRemoteChainId == 0 || authorizedRemoteContract == address(0)) {
            revert TrustedRemoteNotConfigured();
        }
        (uint256 messageChainId, address messageContract) = inbox.inboxMsgSender();
        if (messageChainId != authorizedRemoteChainId || messageContract != authorizedRemoteContract) {
            revert UntrustedRemoteCaller(messageChainId, messageContract);
        }
        _;
    }

    // --- Constructor ---

    /// @param inboxAddress COTI-side inbox allowed to deliver remote pToken requests.
    /// @param initialOwner Owner allowed to configure the authorized source peer.
    constructor(address inboxAddress, address initialOwner) Ownable(initialOwner) {
        _initializePodErc20CotiSide(inboxAddress, initialOwner);
    }

    // --- External: owner ---

    /**
     * @notice Configures which remote `PodERC20` may drive this contract through the inbox.
     * @dev Reverts if `chainId` or `remotePodToken` is zero.
     */
    function setAuthorizedRemote(uint256 chainId, address remotePodToken) external onlyOwner {
        if (chainId == 0 || remotePodToken == address(0)) {
            revert InvalidAuthorizedRemotePeer();
        }
        authorizedRemoteChainId = chainId;
        authorizedRemoteContract = remotePodToken;
        emit AuthorizedRemoteUpdated(chainId, remotePodToken);
    }

    /// @notice Initialize shared constructor/clone storage.
    /// @param inboxAddress COTI-side inbox allowed to deliver remote pToken requests.
    /// @param initialOwner Owner allowed to configure the authorized source peer.
    function _initializePodErc20CotiSide(address inboxAddress, address initialOwner) internal {
        if (_cotiSideInitialized) {
            revert PodErc20CotiSideAlreadyInitialized();
        }
        if (inboxAddress == address(0) || initialOwner == address(0)) {
            revert PodErc20CotiSideInvalidInitialization();
        }
        _cotiSideInitialized = true;
        setInbox(inboxAddress);
        _transferOwnership(initialOwner);
        emit CotiSideInitialized(inboxAddress, initialOwner);
    }

    /**
     * @inheritdoc IPodErc20CotiSide
     * @dev Increments {nonce} after mint. **Gotcha:** does not increase ERC-20 `totalSupply` on PoD—supply is a deployment concern.
     */
    function ownerMint(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) {
            revert MintToZeroAddress();
        }
        ctUint256 memory ct = _balanceCiphertext[to];
        if (_isEmptyCtUint256(ct)) {
            _balanceCiphertext[to] = MpcCore.offBoard(MpcCore.setPublic256(amount));
        } else {
            gtUint256 memory cur = MpcCore.onBoard(ct);
            _balanceCiphertext[to] = MpcCore.offBoard(MpcCore.add(cur, MpcCore.setPublic256(amount)));
        }
        nonce++;
        emit OwnerMinted(to, amount, nonce);
    }

    // --- External: inbox + authorized remote ---

    /// @inheritdoc IPodErc20CotiSide
    function syncBalances(address[] calldata accounts) external override onlyAuthorizedPodTokenMessage {
        if (accounts.length == 0) {
            _sendSyncFailureToPod(bytes("PodErc20CotiSide: empty accounts"));
            return;
        }

        uint256 count = accounts.length;
        address[] memory addresses = new address[](count);
        ctUint256[] memory ciphertextAmounts = new ctUint256[](count);

        for (uint256 i = 0; i < count; ++i) {
            address account = accounts[i];
            addresses[i] = account;
            gtUint256 memory garbledBalance = _readGarbledBalance(account);
            ciphertextAmounts[i] = MpcCore.offBoardToUser(garbledBalance, account);
        }

        uint256 callbackNonce = nonce;
        inbox.respond(abi.encode(addresses, ciphertextAmounts, callbackNonce));
        emit SyncBalancesResponded(addresses, callbackNonce);
        nonce = callbackNonce + 1;
    }

    /// @inheritdoc IPodErc20CotiSide
    function transfer(address from, address to, gtUint256 calldata value) external override onlyAuthorizedPodTokenMessage {
        _moveOrBurn(from, to, _garbledFromCalldata(value), false, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferPublic(address from, address to, uint256 value) external override onlyAuthorizedPodTokenMessage {
        _moveOrBurn(from, to, MpcCore.setPublic256(value), false, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFrom(
        address from,
        address to,
        gtUint256 calldata value
    ) external override onlyAuthorizedPodTokenMessage {
        _moveOrBurn(from, to, _garbledFromCalldata(value), false, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFromPublic(
        address from,
        address to,
        uint256 value
    ) external override onlyAuthorizedPodTokenMessage {
        _moveOrBurn(from, to, MpcCore.setPublic256(value), false, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFromAsSpender(
        address spender,
        address from,
        address to,
        gtUint256 calldata value
    ) external override onlyAuthorizedPodTokenMessage {
        _moveWithOptionalAllowance(spender, from, to, _garbledFromCalldata(value), true, false, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFromPublicAsSpender(
        address spender,
        address from,
        address to,
        uint256 value
    ) external override onlyAuthorizedPodTokenMessage {
        _moveWithOptionalAllowance(spender, from, to, MpcCore.setPublic256(value), true, false, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function approve(
        address owner,
        address spender,
        gtUint256 calldata value
    ) external override onlyAuthorizedPodTokenMessage {
        _approveInternal(owner, spender, _garbledFromCalldata(value), false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function approvePublic(
        address owner,
        address spender,
        uint256 value
    ) external override onlyAuthorizedPodTokenMessage {
        _approveInternal(owner, spender, MpcCore.setPublic256(value), true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function burn(address from, gtUint256 calldata value) external override onlyAuthorizedPodTokenMessage {
        _moveOrBurn(from, address(0), _garbledFromCalldata(value), true, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function burnPublic(address from, uint256 value) external override onlyAuthorizedPodTokenMessage {
        _moveOrBurn(from, address(0), MpcCore.setPublic256(value), true, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function mint(address to, gtUint256 calldata value) external override onlyAuthorizedPodTokenMessage {
        _mintInternal(to, _garbledFromCalldata(value), false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function mintPublic(address to, uint256 value) external override onlyAuthorizedPodTokenMessage {
        _mintInternal(to, MpcCore.setPublic256(value), true, value);
    }

    // --- Private: garbled balance helpers ---

    /// @dev Copies `gtUint256` from calldata into memory for `MpcCore` APIs.
    function _garbledFromCalldata(gtUint256 calldata value) private pure returns (gtUint256 memory garbled) {
        garbled = value;
    }

    /// @dev Plain zero as ciphertext (for burn “to” side in the callback tuple and empty-balance `onBoard` input).
    function _ciphertextPlainZero() private returns (ctUint256 memory) {
        return MpcCore.offBoard(MpcCore.setPublic256(0));
    }

    /// @dev All ciphertext limbs zero → treat slot as uninitialized (same idea as {PErc20Coti} `ctUint64.unwrap == 0`).
    function _isEmptyCtUint256(ctUint256 memory ct) private pure returns (bool) {
        return ctUint64.unwrap(ct.high.high) == 0 && ctUint64.unwrap(ct.high.low) == 0
            && ctUint64.unwrap(ct.low.high) == 0 && ctUint64.unwrap(ct.low.low) == 0;
    }

    function _readGarbledBalance(address account) private returns (gtUint256 memory) {
        ctUint256 memory ct = _balanceCiphertext[account];
        if (_isEmptyCtUint256(ct)) {
            return MpcCore.onBoard(_ciphertextPlainZero());
        }
        return MpcCore.onBoard(ct);
    }

    function _writeGarbledBalance(address account, gtUint256 memory newBalance) private {
        _balanceCiphertext[account] = MpcCore.offBoard(newBalance);
    }

    /**
     * @dev Validates addresses, checks `ge(balance, amount)` via decrypt, updates storage, then `respond` or `raise`.
     * @dev **Gotcha:** insufficient balance uses `raise` (PoD sees `transferError`), not a revert.
     */
    function _moveOrBurn(
        address from,
        address to,
        gtUint256 memory amount,
        bool burning,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        _moveWithOptionalAllowance(address(0), from, to, amount, false, burning, amountIsPublic, publicAmount);
    }

    function _moveWithOptionalAllowance(
        address spender,
        address from,
        address to,
        gtUint256 memory amount,
        bool spendAllowance,
        bool burning,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        if (from == address(0)) {
            _sendTransferFailureToPod(from, to, bytes("PodErc20CotiSide: zero from"));
            return;
        }
        if (!burning && to == address(0)) {
            _sendTransferFailureToPod(from, to, bytes("PodErc20CotiSide: zero to"));
            return;
        }

        gtUint256 memory senderBalance = _readGarbledBalance(from);

        if (!MpcCore.decrypt(MpcCore.ge(senderBalance, amount))) {
            _sendTransferFailureToPod(from, to, bytes("PodErc20CotiSide: insufficient balance"));
            return;
        }

        gtUint256 memory allowanceAfter;
        if (spendAllowance && spender != from) {
            gtUint256 memory currentAllowance = _readGarbledAllowance(from, spender);
            if (!MpcCore.decrypt(MpcCore.ge(currentAllowance, amount))) {
                _sendTransferFailureToPod(from, to, bytes("PodErc20CotiSide: insufficient allowance"));
                return;
            }
            allowanceAfter = MpcCore.sub(currentAllowance, amount);
        }

        gtUint256 memory senderAfter = MpcCore.sub(senderBalance, amount);
        _writeGarbledBalance(from, senderAfter);
        if (spendAllowance && spender != from) {
            _allowanceCiphertext[from][spender] = MpcCore.offBoard(allowanceAfter);
        }

        if (burning) {
            ctUint256 memory zeroCiphertext = _ciphertextPlainZero();
            uint256 burnNonce = nonce;
            inbox.respond(
                abi.encode(
                    from,
                    MpcCore.offBoardToUser(senderAfter, from),
                    MpcCore.offBoardToUser(amount, from),
                    address(0),
                    zeroCiphertext,
                    zeroCiphertext,
                    burnNonce
                )
            );
            emit BurnCompleted(from, amountIsPublic, publicAmount, burnNonce);
            nonce = burnNonce + 1;
            return;
        }

        gtUint256 memory recipientBefore = _readGarbledBalance(to);
        gtUint256 memory recipientAfter = MpcCore.add(recipientBefore, amount);
        _writeGarbledBalance(to, recipientAfter);

        uint256 transferNonce = nonce;
        inbox.respond(_encodePodTransferCallback(from, to, amount, senderAfter, recipientAfter, transferNonce));
        emit TransferCompleted(spender, from, to, spendAllowance && spender != from, amountIsPublic, publicAmount, transferNonce);
        nonce = transferNonce + 1;
    }

    function _readGarbledAllowance(address owner, address spender) private returns (gtUint256 memory) {
        ctUint256 memory ct = _allowanceCiphertext[owner][spender];
        if (_isEmptyCtUint256(ct)) {
            return MpcCore.onBoard(_ciphertextPlainZero());
        }
        return MpcCore.onBoard(ct);
    }

    function _encodePodTransferCallback(
        address from,
        address to,
        gtUint256 memory amount,
        gtUint256 memory senderBalanceAfter,
        gtUint256 memory recipientBalanceAfter,
        uint256 callbackNonce
    ) private returns (bytes memory) {
        ctUint256 memory senderBalanceCt = MpcCore.offBoardToUser(senderBalanceAfter, from);
        ctUint256 memory amountForSender = MpcCore.offBoardToUser(amount, from);
        ctUint256 memory recipientBalanceCt = MpcCore.offBoardToUser(recipientBalanceAfter, to);
        ctUint256 memory amountForRecipient = MpcCore.offBoardToUser(amount, to);
        return abi.encode(from, senderBalanceCt, amountForSender, to, recipientBalanceCt, amountForRecipient, callbackNonce);
    }

    /**
     * @dev Sets the garbled allowance for `(owner, spender)` and responds with owner/spender ciphertexts,
     *      or `raise`s if either address is zero (PoD sees `approveError`).
     */
    function _approveInternal(
        address owner,
        address spender,
        gtUint256 memory garbledAllowance,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        if (owner == address(0) || spender == address(0)) {
            _sendApproveFailureToPod(owner, spender, bytes("PodErc20CotiSide: zero owner or spender"));
            return;
        }

        _allowanceCiphertext[owner][spender] = MpcCore.offBoard(garbledAllowance);

        ctUint256 memory ciphertextForOwner = MpcCore.offBoardToUser(garbledAllowance, owner);
        ctUint256 memory ciphertextForSpender = MpcCore.offBoardToUser(garbledAllowance, spender);
        inbox.respond(abi.encode(owner, ciphertextForOwner, spender, ciphertextForSpender));
        emit ApprovalCompleted(owner, spender, amountIsPublic, publicAmount);
    }

    /**
     * @dev Adds `amount` to `to`'s garbled balance and responds with a transfer-callback-shaped tuple where `from == address(0)`.
     *      On a zero recipient the contract `raise`s so PoD surfaces a `transferError`.
     */
    function _mintInternal(address to, gtUint256 memory amount, bool amountIsPublic, uint256 publicAmount) private {
        if (to == address(0)) {
            _sendTransferFailureToPod(address(0), to, bytes("PodErc20CotiSide: mint zero to"));
            return;
        }

        gtUint256 memory recipientBefore = _readGarbledBalance(to);
        gtUint256 memory recipientAfter = MpcCore.add(recipientBefore, amount);
        _writeGarbledBalance(to, recipientAfter);

        ctUint256 memory zeroCiphertext = _ciphertextPlainZero();
        uint256 callbackNonce = nonce;
        inbox.respond(
            abi.encode(
                address(0),
                zeroCiphertext,
                zeroCiphertext,
                to,
                MpcCore.offBoardToUser(recipientAfter, to),
                MpcCore.offBoardToUser(amount, to),
                callbackNonce
            )
        );
        emit MintCompleted(to, amountIsPublic, publicAmount, callbackNonce);
        nonce = callbackNonce + 1;
    }

    function _sendTransferFailureToPod(address from, address to, bytes memory reason) private {
        emit TransferFailureRaised(from, to, reason);
        inbox.raise(abi.encode(from, to, reason));
    }

    function _sendApproveFailureToPod(address owner, address spender, bytes memory reason) private {
        emit ApprovalFailureRaised(owner, spender, reason);
        inbox.raise(abi.encode(owner, spender, reason));
    }

    function _sendSyncFailureToPod(bytes memory reason) private {
        emit SyncBalancesFailureRaised(reason);
        inbox.raise(reason);
    }
}
