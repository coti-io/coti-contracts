// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/// @title IPodERC20
/// @notice Async private ERC-20: `ctUint256` balances/allowances; moves use `itUint256` and inbox + COTI settlement.
/// @dev Not IERC20-compatible: mutating calls return `requestId`; only the configured COTI peer may complete callbacks.
///      Plain `uint256` methods expose amounts in calldata and events; use encrypted `itUint256` methods for privacy-sensitive flows.
interface IPodERC20 {
    // --- Types ---

    enum RequestStatus {
        None,
        Pending,
        Success,
        Failed
    }

    /// @notice Allowance represented twice: re-encrypted for the owner and for the spender so each party can decrypt their view.
    struct Allowance {
        ctUint256 ownerCiphertext;
        ctUint256 spenderCiphertext;
    }

    /// @notice Off-chain helpers may track submitted transfer intents by `requestId`.
    struct TransferRequested {
        address from;
        address to;
        bytes32 requestId;
    }

    /// @notice Off-chain helpers may track submitted approvals by `requestId`.
    struct ApprovalRequested {
        address owner;
        address spender;
        bytes32 requestId;
    }

    /// @notice EIP-712 permit data used by public transferFrom flows that should not wait for async approve.
    struct PublicPermit {
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // --- Events ---

    /**
     * @notice Tokens moved from `from` to `to` after the COTI leg succeeded and this contract applied ciphertext updates.
     * @dev `senderValue` / `receiverValue` are the same logical amount re-encrypted for each party; either may be zero in edge cases.
     */
    event Transfer(
        address indexed from,
        address indexed to,
        ctUint256 senderValue,
        ctUint256 receiverValue
    );

    /// @notice The asynchronous transfer failed on the COTI side or was rejected before balances were updated.
    event TransferFailed(address indexed from, address indexed to, bytes errorMsg);

    /**
     * @notice Allowance for `spender` on `owner` was updated after a successful COTI `approve`.
     * @dev `ownerValue` and `spenderValue` encrypt the same allowance amount for different AES keys.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        ctUint256 ownerValue,
        ctUint256 spenderValue
    );

    /// @notice `transferAndCall` delivered tokens but the post-transfer `to.call(callbackData)` reverted or ran out of gas.
    event RequestCallbackFailed(address from, address to, bytes32 requestId, bytes callbackData);

    /// @notice `syncBalances` refreshed `account` from the COTI ledger when the monotonic `nonce` allowed it.
    event BalanceSynced(address account, ctUint256 amount);

    /// @notice Lifecycle transition for an async inbox request submitted by this token.
    event RequestStatusUpdated(bytes32 indexed requestId, RequestStatus status);

    // --- Token metadata & supply ---

    /**
     * @notice ERC-20-style total supply accessor.
     * @dev Implementations may always return `0` to hide supply on-chain while the authoritative ledger lives on COTI.
     */
    function totalSupply() external view returns (uint256);

    /// @notice Status of an async request submitted by this token.
    function requests(bytes32 requestId) external view returns (RequestStatus);

    // --- Balances ---

    /**
     * @notice Returns `account`'s balance as ciphertext encrypted for that account.
     * @dev Stale reads are possible if a transfer is in flight; see {balanceOfWithStatus}.
     */
    function balanceOf(address account) external view returns (ctUint256 memory);

    /**
     * @notice Same as {balanceOf}, plus whether this account is currently locked by an in-flight transfer (or burn).
     * @dev While `pending` is true, new transfers involving this address as `from` or `to` will revert.
     */
    function balanceOfWithStatus(address account) external view returns (ctUint256 memory, bool pending);

    // --- Transfers ---

    /**
     * @notice Starts an encrypted transfer of `value` from the caller to `to`.
     * @return requestId Inbox request id; completion is asynchronous via {Transfer} or {TransferFailed}.
     * @dev **Gotcha:** reverts if either the sender or `to` already has a pending transfer. **Gotcha:** concurrent approvals use a
     *      separate pending map and do not block transfers unless your deployment couples them elsewhere.
     * @param callbackFeeLocalWei Caller-estimated wei slice for the callback leg; total payment is `msg.value`.
     */
    function transfer(address to, itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Starts an encrypted transfer of `value` from the caller to `to`.
     * @return requestId Inbox request id; completion is asynchronous via {Transfer} or {TransferFailed}.
     * @dev The callback fee is calculated within the contract
     */
    function transfer(address to, itUint256 calldata value) external payable returns (bytes32 requestId);

    /**
     * @notice Starts a transfer from `from` to `to` using allowance granted to `msg.sender`.
     * @dev **Gotcha:** allowance checks and consumption happen on COTI; this entry point only forwards the MPC call.
     */
    function transferFrom(address from, address to, itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Starts a transfer from `from` to `to` using allowance granted to `msg.sender`.
     * @dev The callback fee is calculated within the contract
     */
    function transferFrom(address from, address to, itUint256 calldata value) external payable returns (bytes32 requestId);

    /**
     * @notice Like {transfer}, then after success attempts `to.call(data)` with no gas stipend beyond the remaining tx gas.
     * @dev **Gotcha:** callback failure does not undo the transfer; it only emits {RequestCallbackFailed}. Stored callback data is cleared on success path.
     */
    function transferAndCall(
        address to,
        itUint256 calldata amount,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Public-amount transferFrom followed by a PoD-side callback to `to` after the COTI transfer succeeds.
     * @dev Uses the caller as spender and consumes allowance on COTI.
     */
    function transferFromAndCall(
        address from,
        address to,
        uint256 amount,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId);

    /**
     * @notice Public-amount transferFrom authorized by a signature, followed by a callback to `to`.
     * @dev Intended for portal withdrawals so users do not wait for a separate async approve.
     */
    function transferFromAndCallWithPermit(
        address from,
        address to,
        uint256 amount,
        PublicPermit calldata permit,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId);

    /// @dev Reserved: re-encrypt the caller's balance for another account's key (not implemented in the reference token).
    // function setAccountEncryptionAddress(address addr) external returns (bytes32 requestId);

    /**
     * @notice Plain-amount transfer variant; the remote leg receives an un-encrypted `uint256` and garbles it on COTI.
     * @dev **Gotcha:** exposes the transfer amount in calldata and events on PoD. Same pending-slot rules as the encrypted overload.
     */
    function transfer(address to, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Plain-amount {transferFrom} variant; see {transfer(address,uint256,uint256)} gotchas.
     */
    function transferFrom(address from, address to, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    // --- Allowances ---

    /**
     * @notice Returns ciphertext views of the allowance; each party decrypts their half.
     * @dev Default is empty/zero ciphertext until an {approve} succeeds.
     */
    function allowance(address owner, address spender) external view returns (Allowance memory);

    /**
     * @notice Same as {allowance}, plus whether an {approve} is already in flight for this pair.
     * @dev While `pending` is true, another {approve} for the same owner/spender reverts.
     */
    function allowanceWithStatus(
        address owner,
        address spender
    ) external view returns (Allowance memory, bool pending);

    /**
     * @notice Sets allowance of `spender` over the caller's tokens to `value` (encrypted input).
     * @return requestId Asynchronous request id for this approval.
     * @dev **Gotcha:** classic ERC-20 allowance front-running applies if you change from non-zero to non-zero in one step;
     *      consider setting to zero first. **Gotcha:** only one pending approval per `(owner, spender)` at a time.
     */
    function approve(address spender, itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Sets allowance of `spender` over the caller's tokens to `value` (encrypted input).
     * @return requestId Asynchronous request id for this approval.
     * @dev The callback fee is calculated within the contract
     */
    function approve(address spender, itUint256 calldata value) external payable returns (bytes32 requestId);

    /**
     * @notice Plain-amount approval variant; the COTI leg garbles `amount` with `MpcCore.setPublic256`.
     * @dev **Gotcha:** exposes the allowance in calldata and events on PoD.
     */
    function approve(address spender, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    // --- Mint / burn ---

    /**
     * @notice Destroys `amount` (encrypted) from the caller on the COTI ledger; PoD balances update on callback.
     * @return requestId Asynchronous burn request.
     * @dev **Gotcha:** uses the same pending-transfer slot as transfers; burns block other transfers for `msg.sender` until settled.
     */
    function burn(itUint256 calldata amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Plain-amount burn variant (non-encrypted input).
     * @dev **Gotcha:** exposes burned amount in calldata; same pending-slot behavior as the encrypted variant.
     */
    function burn(uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Mints `amount` (encrypted) into `to` on the COTI ledger; PoD balance for `to` updates on callback.
     * @return requestId Asynchronous mint request.
     * @dev **Gotcha:** uses the same pending-transfer slot as transfers for the recipient; the `from` side of the callback is `address(0)`.
     */
    function mint(address to, itUint256 calldata amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /**
     * @notice Plain-amount mint variant; COTI garbles via `MpcCore.setPublic256`.
     * @dev **Gotcha:** exposes minted amount in calldata.
     */
    function mint(address to, uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);

    /// @dev Reserved: burn garbled amount; not supported in reference flows.
    // function burnGt(gtUint256 amount) external returns (gtBool);

    /// @dev Reserved: `transferFrom` with garbled amount; not supported.
    // function transferFromGT(address from, address to, gtUint256 value) external returns (gtBool);

    // --- Sync ---

    /**
     * @notice Pulls fresh garbled balances from COTI for `accounts` and applies them on success if the sync `nonce` is newer.
     * @return requestId Two-way inbox request id.
     * @dev **Gotcha:** large account lists mean heavy MPC work and gas on COTI; empty list may fail on the COTI side.
     */
    function syncBalances(address[] calldata accounts, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId);
}
