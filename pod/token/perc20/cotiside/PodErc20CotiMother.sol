// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../../utils/mpc/MpcCore.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "../../../InboxUser.sol";
import "./IPodErc20CotiSide.sol";

/// @title PodErc20CotiMother
/// @notice Unified COTI-side ledger for all paired {PodERC20} tokens. Balances are namespaced by `(sourceChainId, sourcePToken)`.
/// @dev Source-chain {PrivacyPortalFactory} registers tokens via one-way inbox messages. MPC ops use {inboxMsgSender} as token context.
contract PodErc20CotiMother is IPodErc20CotiSide, InboxUser, Ownable {
    // --- Types ---

    struct TokenMeta {
        string name;
        string symbol;
        uint8 decimals;
    }

    // --- State variables ---

    /// @dev Per-token monotonic nonce included in PoD callbacks. Starts at 1 on registration so the first
    ///      callback satisfies PoD `balanceNonces[account] < nonce` (PoD nonces default to 0).
    mapping(bytes32 => uint256) private _tokenNonce;
    uint256 private constant INITIAL_TOKEN_NONCE = 1;
    /// @dev Balance ciphertext per token and account.
    mapping(bytes32 => mapping(address => ctUint256)) private _balanceCiphertext;
    /// @dev Allowance ciphertext per token: `owner => spender => ctUint256`.
    mapping(bytes32 => mapping(address => mapping(address => ctUint256))) private _allowanceCiphertext;
    /// @dev Whether a `(sourceChainId, remotePToken)` namespace is registered.
    mapping(bytes32 => bool) public registered;
    /// @dev Public metadata recorded at registration.
    mapping(bytes32 => TokenMeta) public tokenMeta;
    /// @dev Allowlisted source-chain factories that may register tokens.
    mapping(uint256 => mapping(address => bool)) public allowedFactories;

    // --- Events ---

    event CotiMotherInitialized(address indexed inbox, address indexed owner);
    event AllowedFactoryUpdated(uint256 indexed sourceChainId, address indexed factory, bool allowed);
    event TokenRegistered(
        uint256 indexed sourceChainId,
        address indexed remotePToken,
        string name,
        string symbol,
        uint8 decimals
    );
    event SyncBalancesResponded(bytes32 indexed tokenId, address[] accounts, uint256 nonce);
    event TransferCompleted(
        bytes32 indexed tokenId,
        address indexed spender,
        address indexed from,
        address to,
        bool allowanceSpent,
        bool amountIsPublic,
        uint256 publicAmount,
        uint256 nonce
    );
    event BurnCompleted(
        bytes32 indexed tokenId,
        address indexed from,
        bool amountIsPublic,
        uint256 publicAmount,
        uint256 nonce
    );
    event MintCompleted(
        bytes32 indexed tokenId,
        address indexed to,
        bool amountIsPublic,
        uint256 publicAmount,
        uint256 nonce
    );
    event ApprovalCompleted(
        bytes32 indexed tokenId,
        address indexed owner,
        address indexed spender,
        bool amountIsPublic,
        uint256 publicAmount
    );
    event TransferFailureRaised(bytes32 indexed tokenId, address indexed from, address indexed to, bytes reason);
    event ApprovalFailureRaised(bytes32 indexed tokenId, address indexed owner, address indexed spender, bytes reason);
    event SyncBalancesFailureRaised(bytes32 indexed tokenId, bytes reason);

    // --- Errors ---

    error InvalidAddress();
    error FactoryNotAllowed(uint256 sourceChainId, address factory);
    error InvalidRemotePToken();
    error TokenAlreadyRegistered(bytes32 tokenId);
    error TokenNotRegistered(bytes32 tokenId);
    error MintToZeroAddress();
    error OwnerMintNotSupported();
    error ChainIdOverflow(uint256 sourceChainId);

    // --- Modifiers ---

    modifier onlyRegisteredFactoryMessage() {
        if (msg.sender != address(inbox)) {
            revert OnlyInbox(msg.sender);
        }
        (uint256 sourceChainId, address factory) = inbox.inboxMsgSender();
        if (!allowedFactories[sourceChainId][factory]) {
            revert FactoryNotAllowed(sourceChainId, factory);
        }
        _;
    }

    modifier onlyRegisteredPTokenMessage() {
        if (msg.sender != address(inbox)) {
            revert OnlyInbox(msg.sender);
        }
        (uint256 sourceChainId, address remotePToken) = inbox.inboxMsgSender();
        bytes32 id = _tokenId(sourceChainId, remotePToken);
        if (!registered[id]) {
            revert TokenNotRegistered(id);
        }
        _;
    }

    // --- Constructor ---

    /// @param inboxAddress COTI-side inbox allowed to deliver remote pToken requests.
    /// @param initialOwner Owner allowed to configure factories.
    constructor(address inboxAddress, address initialOwner) Ownable(initialOwner) {
        if (inboxAddress == address(0) || initialOwner == address(0)) {
            revert InvalidAddress();
        }
        setInbox(inboxAddress);
        emit CotiMotherInitialized(inboxAddress, initialOwner);
    }

    // --- External: views ---

    /// @notice Compute the namespace id for a source-chain pToken.
    function tokenId(uint256 sourceChainId, address remotePToken) public pure returns (bytes32) {
        return _tokenId(sourceChainId, remotePToken);
    }

    /// @notice Whether a source-chain pToken namespace is registered.
    function isRegistered(uint256 sourceChainId, address remotePToken) external view returns (bool) {
        return registered[_tokenId(sourceChainId, remotePToken)];
    }

    // --- External: owner ---

    /// @notice Allow or disallow a source-chain factory to register tokens.
    function setAllowedFactory(uint256 sourceChainId, address factory, bool allowed) external onlyOwner {
        if (sourceChainId == 0 || factory == address(0)) {
            revert InvalidAddress();
        }
        allowedFactories[sourceChainId][factory] = allowed;
        emit AllowedFactoryUpdated(sourceChainId, factory, allowed);
    }

    /// @inheritdoc IPodErc20CotiSide
    /// @dev Not supported on the unified mother ledger; mint via inbox {mintPublic} from the paired pToken minter.
    function ownerMint(address, uint256) external pure override {
        revert OwnerMintNotSupported();
    }

    // --- External: registration ---

    /// @notice Register a new source-chain pToken namespace. Callable only via inbox from an allowlisted factory.
    function registerToken(
        address remotePToken,
        string calldata name,
        string calldata symbol,
        uint8 decimals
    ) external onlyRegisteredFactoryMessage {
        if (remotePToken == address(0)) {
            revert InvalidRemotePToken();
        }

        (uint256 sourceChainId,) = inbox.inboxMsgSender();
        bytes32 id = _tokenId(sourceChainId, remotePToken);
        if (registered[id]) {
            revert TokenAlreadyRegistered(id);
        }

        registered[id] = true;
        tokenMeta[id] = TokenMeta(name, symbol, decimals);
        _tokenNonce[id] = INITIAL_TOKEN_NONCE;
        emit TokenRegistered(sourceChainId, remotePToken, name, symbol, decimals);
    }

    // --- External: inbox + registered pToken ---

    /// @inheritdoc IPodErc20CotiSide
    function syncBalances(address[] calldata accounts) external override onlyRegisteredPTokenMessage {
        bytes32 id = _activeTokenId();
        if (accounts.length == 0) {
            _sendSyncFailureToPod(id, bytes("PodErc20CotiMother: empty accounts"));
            return;
        }

        uint256 count = accounts.length;
        address[] memory addresses = new address[](count);
        ctUint256[] memory ciphertextAmounts = new ctUint256[](count);

        for (uint256 i = 0; i < count; ++i) {
            address account = accounts[i];
            addresses[i] = account;
            gtUint256 garbledBalance = _readGarbledBalance(id, account);
            ciphertextAmounts[i] = MpcCore.offBoardToUser(garbledBalance, account);
        }

        uint256 callbackNonce = _tokenNonce[id];
        inbox.respond(abi.encode(addresses, ciphertextAmounts, callbackNonce));
        emit SyncBalancesResponded(id, addresses, callbackNonce);
        _tokenNonce[id] = callbackNonce + 1;
    }

    /// @inheritdoc IPodErc20CotiSide
    function transfer(address from, address to, gtUint256 value) external override onlyRegisteredPTokenMessage {
        _moveOrBurn(_activeTokenId(), from, to, value, false, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferPublic(address from, address to, uint256 value) external override onlyRegisteredPTokenMessage {
        _moveOrBurn(_activeTokenId(), from, to, MpcCore.setPublic256(value), false, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFrom(
        address from,
        address to,
        gtUint256 value
    ) external override onlyRegisteredPTokenMessage {
        _moveOrBurn(_activeTokenId(), from, to, value, false, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFromPublic(
        address from,
        address to,
        uint256 value
    ) external override onlyRegisteredPTokenMessage {
        _moveOrBurn(_activeTokenId(), from, to, MpcCore.setPublic256(value), false, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFromAsSpender(
        address spender,
        address from,
        address to,
        gtUint256 value
    ) external override onlyRegisteredPTokenMessage {
        _moveWithOptionalAllowance(
            _activeTokenId(), spender, from, to, value, true, false, false, 0
        );
    }

    /// @inheritdoc IPodErc20CotiSide
    function transferFromPublicAsSpender(
        address spender,
        address from,
        address to,
        uint256 value
    ) external override onlyRegisteredPTokenMessage {
        _moveWithOptionalAllowance(
            _activeTokenId(), spender, from, to, MpcCore.setPublic256(value), true, false, true, value
        );
    }

    /// @inheritdoc IPodErc20CotiSide
    function approve(
        address owner,
        address spender,
        gtUint256 value
    ) external override onlyRegisteredPTokenMessage {
        _approveInternal(_activeTokenId(), owner, spender, value, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function approvePublic(
        address owner,
        address spender,
        uint256 value
    ) external override onlyRegisteredPTokenMessage {
        _approveInternal(_activeTokenId(), owner, spender, MpcCore.setPublic256(value), true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function burn(address from, gtUint256 value) external override onlyRegisteredPTokenMessage {
        _moveOrBurn(_activeTokenId(), from, address(0), value, true, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function burnPublic(address from, uint256 value) external override onlyRegisteredPTokenMessage {
        _moveOrBurn(_activeTokenId(), from, address(0), MpcCore.setPublic256(value), true, true, value);
    }

    /// @inheritdoc IPodErc20CotiSide
    function mint(address to, gtUint256 value) external override onlyRegisteredPTokenMessage {
        _mintInternal(_activeTokenId(), to, value, false, 0);
    }

    /// @inheritdoc IPodErc20CotiSide
    function mintPublic(address to, uint256 value) external override onlyRegisteredPTokenMessage {
        _mintInternal(_activeTokenId(), to, MpcCore.setPublic256(value), true, value);
    }

    // --- Internal: token context ---

    /// @dev Packs `sourceChainId` (uint64) in the high 64 bits and `remotePToken` (uint160) in the low 160 bits.
    function _tokenId(uint256 sourceChainId, address remotePToken) internal pure returns (bytes32) {
        if (sourceChainId > type(uint64).max) {
            revert ChainIdOverflow(sourceChainId);
        }
        return bytes32((uint256(uint64(sourceChainId)) << 160) | uint256(uint160(remotePToken)));
    }

    function _activeTokenId() internal view returns (bytes32) {
        (uint256 sourceChainId, address remotePToken) = inbox.inboxMsgSender();
        return _tokenId(sourceChainId, remotePToken);
    }

    // --- Private: garbled balance helpers ---

    function _ciphertextPlainZero() private returns (ctUint256 memory) {
        return MpcCore.offBoard(MpcCore.setPublic256(0));
    }

    function _isEmptyCtUint256(ctUint256 memory ct) private pure returns (bool) {
        return ctUint128.unwrap(ct.ciphertextHigh) == 0 && ctUint128.unwrap(ct.ciphertextLow) == 0;
    }

    function _readGarbledBalance(bytes32 id, address account) private returns (gtUint256) {
        ctUint256 memory ct = _balanceCiphertext[id][account];
        if (_isEmptyCtUint256(ct)) {
            return MpcCore.onBoard(_ciphertextPlainZero());
        }
        return MpcCore.onBoard(ct);
    }

    function _writeGarbledBalance(bytes32 id, address account, gtUint256 newBalance) private {
        _balanceCiphertext[id][account] = MpcCore.offBoard(newBalance);
    }

    function _moveOrBurn(
        bytes32 id,
        address from,
        address to,
        gtUint256 amount,
        bool burning,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        _moveWithOptionalAllowance(id, address(0), from, to, amount, false, burning, amountIsPublic, publicAmount);
    }

    function _moveWithOptionalAllowance(
        bytes32 id,
        address spender,
        address from,
        address to,
        gtUint256 amount,
        bool spendAllowance,
        bool burning,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        if (from == address(0)) {
            _sendTransferFailureToPod(id, from, to, bytes("PodErc20CotiMother: zero from"));
            return;
        }
        if (!burning && to == address(0)) {
            _sendTransferFailureToPod(id, from, to, bytes("PodErc20CotiMother: zero to"));
            return;
        }

        gtUint256 senderBalance = _readGarbledBalance(id, from);

        if (!MpcCore.decrypt(MpcCore.ge(senderBalance, amount))) {
            _sendTransferFailureToPod(id, from, to, bytes("PodErc20CotiMother: insufficient balance"));
            return;
        }

        gtUint256 allowanceAfter;
        if (spendAllowance && spender != from) {
            gtUint256 currentAllowance = _readGarbledAllowance(id, from, spender);
            if (!MpcCore.decrypt(MpcCore.ge(currentAllowance, amount))) {
                _sendTransferFailureToPod(id, from, to, bytes("PodErc20CotiMother: insufficient allowance"));
                return;
            }
            allowanceAfter = MpcCore.sub(currentAllowance, amount);
        }

        gtUint256 senderAfter = MpcCore.sub(senderBalance, amount);
        _writeGarbledBalance(id, from, senderAfter);
        if (spendAllowance && spender != from) {
            _allowanceCiphertext[id][from][spender] = MpcCore.offBoard(allowanceAfter);
        }

        if (burning) {
            ctUint256 memory zeroCiphertext = _ciphertextPlainZero();
            uint256 burnNonce = _tokenNonce[id];
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
            emit BurnCompleted(id, from, amountIsPublic, publicAmount, burnNonce);
            _tokenNonce[id] = burnNonce + 1;
            return;
        }

        gtUint256 recipientBefore = _readGarbledBalance(id, to);
        gtUint256 recipientAfter = MpcCore.add(recipientBefore, amount);
        _writeGarbledBalance(id, to, recipientAfter);

        uint256 transferNonce = _tokenNonce[id];
        inbox.respond(_encodePodTransferCallback(from, to, amount, senderAfter, recipientAfter, transferNonce));
        emit TransferCompleted(
            id, spender, from, to, spendAllowance && spender != from, amountIsPublic, publicAmount, transferNonce
        );
        _tokenNonce[id] = transferNonce + 1;
    }

    function _readGarbledAllowance(bytes32 id, address owner, address spender) private returns (gtUint256) {
        ctUint256 memory ct = _allowanceCiphertext[id][owner][spender];
        if (_isEmptyCtUint256(ct)) {
            return MpcCore.onBoard(_ciphertextPlainZero());
        }
        return MpcCore.onBoard(ct);
    }

    function _encodePodTransferCallback(
        address from,
        address to,
        gtUint256 amount,
        gtUint256 senderBalanceAfter,
        gtUint256 recipientBalanceAfter,
        uint256 callbackNonce
    ) private returns (bytes memory) {
        ctUint256 memory senderBalanceCt = MpcCore.offBoardToUser(senderBalanceAfter, from);
        ctUint256 memory amountForSender = MpcCore.offBoardToUser(amount, from);
        ctUint256 memory recipientBalanceCt = MpcCore.offBoardToUser(recipientBalanceAfter, to);
        ctUint256 memory amountForRecipient = MpcCore.offBoardToUser(amount, to);
        return abi.encode(from, senderBalanceCt, amountForSender, to, recipientBalanceCt, amountForRecipient, callbackNonce);
    }

    function _approveInternal(
        bytes32 id,
        address owner,
        address spender,
        gtUint256 garbledAllowance,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        if (owner == address(0) || spender == address(0)) {
            _sendApproveFailureToPod(id, owner, spender, bytes("PodErc20CotiMother: zero owner or spender"));
            return;
        }

        _allowanceCiphertext[id][owner][spender] = MpcCore.offBoard(garbledAllowance);

        ctUint256 memory ciphertextForOwner = MpcCore.offBoardToUser(garbledAllowance, owner);
        ctUint256 memory ciphertextForSpender = MpcCore.offBoardToUser(garbledAllowance, spender);
        inbox.respond(abi.encode(owner, ciphertextForOwner, spender, ciphertextForSpender));
        emit ApprovalCompleted(id, owner, spender, amountIsPublic, publicAmount);
    }

    function _mintInternal(
        bytes32 id,
        address to,
        gtUint256 amount,
        bool amountIsPublic,
        uint256 publicAmount
    ) private {
        if (to == address(0)) {
            _sendTransferFailureToPod(id, address(0), to, bytes("PodErc20CotiMother: mint zero to"));
            return;
        }

        gtUint256 recipientBefore = _readGarbledBalance(id, to);
        gtUint256 recipientAfter = MpcCore.add(recipientBefore, amount);
        _writeGarbledBalance(id, to, recipientAfter);

        ctUint256 memory zeroCiphertext = _ciphertextPlainZero();
        uint256 callbackNonce = _tokenNonce[id];
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
        emit MintCompleted(id, to, amountIsPublic, publicAmount, callbackNonce);
        _tokenNonce[id] = callbackNonce + 1;
    }

    function _sendTransferFailureToPod(bytes32 id, address from, address to, bytes memory reason) private {
        emit TransferFailureRaised(id, from, to, reason);
        inbox.raise(abi.encode(from, to, reason));
    }

    function _sendApproveFailureToPod(bytes32 id, address owner, address spender, bytes memory reason) private {
        emit ApprovalFailureRaised(id, owner, spender, reason);
        inbox.raise(abi.encode(owner, spender, reason));
    }

    function _sendSyncFailureToPod(bytes32 id, bytes memory reason) private {
        emit SyncBalancesFailureRaised(id, reason);
        inbox.raise(reason);
    }
}
