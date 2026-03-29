// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IPrivateERC20} from "./IPrivateERC20.sol";
import {ITokenReceiver} from "./ITokenReceiver.sol";
import {ITokenReceiverEncrypted} from "./ITokenReceiverEncrypted.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../../utils/mpc/MpcCore.sol";

/*
THIS IS THE 256 BIT VERSION OF PRIVATE ERC20.

Key Features:
- Full uint256 support (no scaling factors)
- AccessControl (for Bridge Integrations)
- ERC165 Support - Tokens Discoverability
- Payable Tokens with TransferAndCall (ERC677-like callback pattern)
- Encrypted Operations (Mint, Burn, Transfer, Approve)

Failure semantics (integrators and contract callers):
- State-changing operations that move value or change supply/allowances are designed to follow a
  revert-on-failure model: if the MPC layer reports that the core update did not succeed, the
  transaction reverts (enforced in {_update} for mint/transfer/burn, and via explicit requires
  where an operation composes multiple steps). Success is therefore implied by a completed call
  that did not revert. Pure/view helpers and read paths that only return ciphertext or onboarded
  values are not “success/failure” token operations in that sense.

Storage encoding ({_safeOnboard} — see implementation NatSpec):
- Uninitialized or zeroed `ctUint256` slots read as both 128-bit limbs zero. The implementation
  treats that as **canonical empty** and maps it to `MpcCore.setPublic256(0)` without calling
  `MpcCore.onBoard` (gas). Any other pattern is onboarded with `MpcCore.onBoard`.
- Successful updates in this contract only write ciphertext via `MpcCore.offBoard` after MPC
  success, so balances, allowances, and aggregate supply stay consistent with the precompile.

Trust assumptions (deploy only when these hold):
- Deploy only on chains where the MPC precompile at address(0x64) is part of the trusted base.
  You explicitly trust that network: its consensus, node/precompile implementation, and upgrade
  policy. All balances and transfers are ultimately defined by MPC results this contract cannot
  independently verify. If the precompile were malicious or buggy, accounting integrity could fail
  in ways Solidity cannot fix on-chain. Optional mitigations (e.g. admin pause, monitoring) only
  limit further damage after suspicion; they do not prove past MPC correctness or roll back state.
  If the chain allows precompile upgrades, consider monitoring and circuit-breakers.
- There is **no** trust-minimized substitute on-chain: auditors and integrators should record which
  chain ID, precompile address, and build/version they rely on, and treat MPC upgrades as **trusted**
  migrations unless your organization runs independent off-chain verification against published specs.
- MINTER_ROLE must only pass valid amounts to mint/mintGt/mint(itUint256). If the MPC layer
  enforces bounds or validity, that dependency applies.
- Minting is bounded by {supplyCap} (override in concrete tokens like {decimals}); enforced in {_update}.
- Integrators — {totalSupply} vs supply: the default {totalSupply} returns 0 and does **not** reflect
  circulating aggregate supply (see {totalSupply} NatSpec). Do not plug this token into protocols that
  assume ERC-20 `totalSupply` semantics. Use {supplyCap} only as the **mint ceiling** parameter; for
  actual supply, use off-chain indexing or a dedicated extension (e.g. auditor reencryption mocks).
- Gas: multiple precompile calls per transfer/approve; no unbounded loops. Document expected
  gas ranges for common operations if needed for integrators.
- Reentrancy: balance/allowance-changing entry points use nonReentrant so a transferAndCall
  receiver cannot nest transferFrom/transfer/approve/increaseAllowance/decreaseAllowance/mint/burn in the same transaction.
- transferAndCall: public-amount overload uses {ITokenReceiver}; encrypted-amount overload uses
  {ITokenReceiverEncrypted} (no plaintext amount in callback). Receivers are still fully trusted
  for callback behavior.
*/

/**
 * @title PrivateERC20
 * @notice Privacy-oriented ERC-20 base whose balances and transfer rules are enforced through MPC (`MpcCore`), not plain EVM arithmetic on cleartext balances.
 * @dev **MPC trust model:** This contract treats the MPC precompile as the source of truth for
 *      garbled/encrypted `uint256` operations. There is no on-chain fallback that validates MPC
 *      soundness. See {IPrivateERC20} trust assumptions and the file-level comment block above for
 *      deployment and integration requirements. Pausing and `AccessControl` mitigate operational
 *      risk; they do not prove MPC correctness retroactively.
 */
abstract contract PrivateERC20 is
    Context,
    ERC165,
    IPrivateERC20,
    AccessControl,
    ReentrancyGuard
{
    uint256 private constant MAX_UINT_256 = type(uint256).max;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @dev Controls whether public uint256 operations are allowed (mint/burn/transfer/transferFrom/approve/transferAndCall with clear values).
    bool public publicAmountsEnabled;

    mapping(address account => address) private _accountEncryptionAddress;

    mapping(address account => utUint256) private _balances;

    mapping(address account => mapping(address spender => Allowance))
        private _allowances;

    ctUint256 private _totalSupply;

    string private _name;

    string private _symbol;

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC20InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC20InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC20InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `spender` to be approved. Used in approvals.
     * @param spender Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC20InvalidSpender(address spender);

    /**
     * @dev Indicates that clear (public) uint256 operations are disabled for this token.
     */
    error PublicAmountsDisabled();

    /**
     * @dev Indicates that transferAndCall was used with a non-contract recipient.
     *      transferAndCall is for contract-to-contract flows; the recipient must have code.
     */
    error TransferAndCallRequiresContract(address to);

    /**
     * @dev Indicates that a transfer to self (from == to) was attempted.
     *      CRITICAL: Self-transfer is explicitly disallowed. The MPC precompile behavior when
     *      from == to is undefined; allowing it could lead to incorrect balance updates or
     *      inconsistent state. All transfer/transferFrom paths go through _transfer and are
     *      therefore protected.
     */
    error ERC20SelfTransferNotAllowed(address account);

    /**
     * @dev Indicates that name or symbol was empty in the constructor.
     */
    error ERC20InvalidMetadata();

    /**
     * @dev Emitted when the admin enables or disables public uint256 operations.
     */
    event PublicAmountsEnabledSet(bool enabled);

    /**
     * @dev Emitted when an account sets or changes its encryption address for balance reencryption.
     */
    event AccountEncryptionAddressSet(address indexed account, address indexed newAddress);

    /**
     * @dev Sets the values for {name} and {symbol}.
     *
     * Both of these values are immutable: they can only be set once during
     * construction.
     */
    constructor(string memory name_, string memory symbol_) {
        if (bytes(name_).length == 0) revert ERC20InvalidMetadata();
        if (bytes(symbol_).length == 0) revert ERC20InvalidMetadata();
        _name = name_;
        _symbol = symbol_;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        publicAmountsEnabled = true;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5.05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the default value returned by this function, unless
     * it's overridden.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IPrivateERC20-balanceOf} and {IPrivateERC20-transfer}.
     */
    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    /**
     * @dev Configurable **upper bound** on how much can be minted in aggregate (checked in {_update} against
     *      the encrypted total in storage). This is **not** “current circulating supply” and **not** a live
     *      substitute for {totalSupply} on a normal ERC-20. Default: `type(uint256).max`.
     *
     *      Override in concrete tokens when a fixed cap is required (e.g. with {decimals} or tokenomics).
     */
    function supplyCap() public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /**
     * @inheritdoc IPrivateERC20
     * @notice Deliberately **not** standard ERC-20 circulating supply: returns `0` in this implementation.
     *
     * Do **not** use for vault share math, pro-rata rewards, or oracles that expect `totalSupply` to reflect
     * aggregate issuance. For the mint **ceiling**, use {supplyCap}. For optional encrypted aggregate supply
     * to a designated party, see examples under `contracts/mocks/token/PrivateERC20/`.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return 0;
    }

    function mint(
        address to,
        uint256 amount
    ) public virtual override onlyRole(MINTER_ROLE) nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        gtUint256 gtAmount = MpcCore.setPublic256(amount);
        _mint(to, gtAmount);
    }

    /**
     * @dev Mint an already-garbled amount without re-wrapping.
     * Intended for contract-to-contract flows that already hold a gtUint256.
     * Trust: MINTER_ROLE must only pass valid amounts. Reverts if {_update} reports MPC failure.
     */
    function mintGt(
        address to,
        gtUint256 gtAmount
    ) public virtual override onlyRole(MINTER_ROLE) nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        _mint(to, gtAmount);
    }

    /**
     * @dev Mint with encrypted (itUint256) amount.
     * Trust: MINTER_ROLE must only pass valid amounts. Reverts if {_update} reports MPC failure.
     */
    function mint(
        address to,
        itUint256 calldata amount
    ) public virtual override onlyRole(MINTER_ROLE) nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        _mint(to, gtAmount);
    }

    function burn(uint256 amount) public virtual override nonReentrant {
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        gtUint256 gtAmount = MpcCore.setPublic256(amount);
        _burn(_msgSender(), gtAmount);
    }

    /**
     * @dev Burn an already-garbled amount without re-wrapping.
     * Intended for contract-to-contract flows that already hold a gtUint256.
     * Reverts if {_update} reports MPC failure.
     */
    function burnGt(gtUint256 gtAmount) public virtual override nonReentrant {
        _burn(_msgSender(), gtAmount);
    }

    /// @dev Reverts if {_update} reports MPC failure.
    function burn(itUint256 calldata amount) public virtual override nonReentrant {
        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        _burn(_msgSender(), gtAmount);
    }

    /**
     * @dev Transfers tokens to `to` then calls onTokenReceived(to, amount, data).
     *      Only use with trusted receivers. `nonReentrant` blocks re-entry into this function and
     *      into other guarded entry points (transfer, transferFrom, approve, burn, mint, etc.);
     *      the receiver must still be trusted for protocol correctness.
     */
    function transferAndCall(
        address to,
        uint256 amount,
        bytes calldata data
    ) public virtual override nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (to.code.length == 0) revert TransferAndCallRequiresContract(to);
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();

        gtUint256 gtAmount = MpcCore.setPublic256(amount);
        address sender = _msgSender();
        _transfer(sender, to, gtAmount);

        require(
            ITokenReceiver(to).onTokenReceived(sender, amount, data),
            "Callback failed"
        );
    }

    /**
     * @dev Transfers an encrypted amount to `to`, then calls {ITokenReceiverEncrypted-onPrivateTransferReceived}.
     *      The callback does **not** receive a plaintext amount (privacy). Receivers must implement
     *      {ITokenReceiverEncrypted}; do not use {ITokenReceiver} for this overload.
     *      Only use with **trusted** receivers; see {transferAndCall(address,uint256,bytes)} for reentrancy scope.
     */
    function transferAndCall(
        address to,
        itUint256 calldata amount,
        bytes calldata data
    ) public virtual override nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (to.code.length == 0) revert TransferAndCallRequiresContract(to);

        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        address sender = _msgSender();
        _transfer(sender, to, gtAmount);

        require(
            ITokenReceiverEncrypted(to).onPrivateTransferReceived(sender, data),
            "Callback failed"
        );
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(AccessControl, ERC165) returns (bool) {
        return
            interfaceId == type(IPrivateERC20).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns the encryption address set for `account` for balance reencryption.
     *
     * Requirements:
     * - `account` must not be the zero address.
     */
    function accountEncryptionAddress(
        address account
    ) public view returns (address) {
        if (account == address(0)) revert ERC20InvalidReceiver(address(0));
        return _accountEncryptionAddress[account];
    }

    /**
     * @dev See {IPrivateERC20-balanceOf}.
     *
     * Requirements:
     * - `account` must not be the zero address.
     */
    function balanceOf(
        address account
    ) public view virtual override returns (ctUint256 memory) {
        if (account == address(0)) revert ERC20InvalidReceiver(address(0));
        return _balances[account].userCiphertext;
    }

    /**
     * @dev See {IPrivateERC20-balanceOf}.
     *      May perform external calls to the MPC precompile via _getBalance.
     *      Do not use in staticcall or view contexts; off-chain code must not assume this is view-safe.
     */
    function balanceOf() public virtual override returns (gtUint256) {
        return _getBalance(_msgSender());
    }

    /**
     * @dev See {IPrivateERC20-setAccountEncryptionAddress}.
     *
     * NOTE: This will not reencrypt your allowances until they are changed
     */
    function setAccountEncryptionAddress(
        address offBoardAddress
    ) public virtual override nonReentrant returns (bool) {
        if (offBoardAddress == address(0)) revert ERC20InvalidReceiver(address(0));

        gtUint256 gtBalance = _getBalance(_msgSender());

        // Compute new user ciphertext first; reverts if precompile fails. Only then update storage
        // so that we never leave _accountEncryptionAddress and userCiphertext out of sync.
        ctUint256 memory newUserCiphertext = MpcCore.offBoardToUser(
            gtBalance,
            offBoardAddress
        );

        address account = _msgSender();
        _accountEncryptionAddress[account] = offBoardAddress;
        _balances[account].userCiphertext = newUserCiphertext;

        emit AccountEncryptionAddressSet(account, offBoardAddress);

        return true;
    }

    /**
     * @dev Enables or disables operations that use clear public uint256 amounts
     *      (mint, burn, transfer, transferFrom, approve, transferAndCall with uint256).
     *      Intended to be called by the token admin to disallow public value usage if desired.
     */
    function setPublicAmountsEnabled(bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        publicAmountsEnabled = enabled;
        emit PublicAmountsEnabledSet(enabled);
    }

    /**
     * @dev See {IPrivateERC20-transfer}.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `value`.
     *
     * Reverts if {_update} reports MPC failure. Success is implied by absence of revert.
     */
    /// @notice Transfer with encrypted (itUint256) amount
    function transfer(
        address to,
        itUint256 calldata value
    ) public virtual override nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address owner = _msgSender();

        gtUint256 gtValue = MpcCore.validateCiphertext(value);

        _transfer(owner, to, gtValue);
    }

    /// @notice Transfer with garbled-text (gtUint256) amount. Reverts if {_update} reports MPC failure.
    function transferGT(
        address to,
        gtUint256 value
    ) public virtual override nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address owner = _msgSender();

        _transfer(owner, to, value);
    }

    /// @notice Transfer with plain public uint256 amount
    function transfer(
        address to,
        uint256 value
    ) public virtual override nonReentrant {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        address owner = _msgSender();

        gtUint256 gtValue = MpcCore.setPublic256(value);

        _transfer(owner, to, gtValue);
    }

    /**
     * @dev See {IPrivateERC20-allowance}.
     *
     * Requirements:
     * - `owner` and `spender` must not be the zero address.
     */
    function allowance(
        address owner,
        address spender
    ) public view virtual override returns (Allowance memory) {
        if (owner == address(0)) revert ERC20InvalidApprover(address(0));
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IPrivateERC20-allowance}.
     *      May perform external calls to the MPC precompile via _safeOnboard.
     *      Do not use in staticcall or view contexts; off-chain code must not assume this is view-safe.
     *
     * Requirements:
     * - `account` must not be the zero address.
     */
    function allowance(
        address account,
        bool isSpender
    ) public virtual override returns (gtUint256) {
        if (account == address(0)) revert ERC20InvalidReceiver(address(0));
        if (isSpender) {
            // Caller is spender; `account` is owner — read _allowances[owner][spender]
            return _safeOnboard(_allowances[account][_msgSender()].ciphertext);
        } else {
            // Caller is owner; `account` is spender — read _allowances[owner][spender]
            return _safeOnboard(_allowances[_msgSender()][account].ciphertext);
        }
    }

    /**
     * @dev Reencrypts the caller's view of an allowance (as owner or spender) using the caller's encryption address.
     *
     * Requirements:
     * - `account` must not be the zero address.
     * - Caller must have an encryption address set (EOA or contract with setAccountEncryptionAddress).
     *
     * Emits an {AllowanceReencrypted} event.
     */
    function reencryptAllowance(
        address account,
        bool isSpender
    ) public virtual nonReentrant {
        if (account == address(0)) revert ERC20InvalidReceiver(address(0));
        address encryptionAddress = _getAccountEncryptionAddress(_msgSender());
        if (encryptionAddress == address(0)) revert ERC20InvalidReceiver(address(0));

        address owner_;
        address spender_;

        if (isSpender) {
            // Caller is spender; `account` is owner — _allowances[owner][spender]
            owner_ = account;
            spender_ = _msgSender();
            Allowance storage allowance_ = _allowances[owner_][spender_];

            allowance_.spenderCiphertext = MpcCore.offBoardToUser(
                _safeOnboard(allowance_.ciphertext),
                encryptionAddress
            );
        } else {
            // Caller is owner; `account` is spender — _allowances[owner][spender]
            owner_ = _msgSender();
            spender_ = account;
            Allowance storage allowance_ = _allowances[owner_][spender_];

            allowance_.ownerCiphertext = MpcCore.offBoardToUser(
                _safeOnboard(allowance_.ciphertext),
                encryptionAddress
            );
        }

        emit AllowanceReencrypted(owner_, spender_, isSpender);
    }

    /**
     * @dev See {IPrivateERC20-approve}.
     *
     * NOTE: If `value` is the maximum `itUint256`, the allowance is not updated on
     * `transferFrom`. This is semantically equivalent to an infinite approval.
     *
     * Reverts with {ERC20UnsafeApprove} if both the current allowance and the new value are
     * non-zero (same mitigation as {approve(address,uint256)}). Prefer {increaseAllowance} or
     * {decreaseAllowance} to change a non-zero allowance without a two-step reset.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    /// @notice Approve with encrypted (itUint256) amount
    function approve(
        address spender,
        itUint256 calldata value
    ) public virtual override nonReentrant  {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        address owner = _msgSender();

        gtUint256 gtValue = MpcCore.validateCiphertext(value);

        _requireSafeEncryptedApprove(owner, spender, gtValue);

        _approve(owner, spender, gtValue);

    }

    /// @notice Approve with garbled-text (gtUint256) amount
    function approveGT(
        address spender,
        gtUint256 value
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        address owner = _msgSender();

        _requireSafeEncryptedApprove(owner, spender, value);

        _approve(owner, spender, value);

    }

    /// @notice Approve with plain public uint256 amount
    function approve(
        address spender,
        uint256 value
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        address owner = _msgSender();

        if (value != 0) {
            gtUint256 currentAllowance = _safeOnboard(
                _allowances[owner][spender].ciphertext
            );
            if (!MpcCore.decrypt(MpcCore.eq(currentAllowance, uint256(0)))) {
                revert ERC20UnsafeApprove();
            }
        }

        gtUint256 gtValue = MpcCore.setPublic256(value);

        _approve(owner, spender, gtValue);
    }

    /// @inheritdoc IPrivateERC20
    function increaseAllowance(
        address spender,
        itUint256 calldata addedValue
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        gtUint256 gtAdded = MpcCore.validateCiphertext(addedValue);
        _increaseAllowance(_msgSender(), spender, gtAdded);
    }

    /// @inheritdoc IPrivateERC20
    function increaseAllowance(
        address spender,
        uint256 addedValue
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        _increaseAllowance(_msgSender(), spender, MpcCore.setPublic256(addedValue));
    }

    /// @inheritdoc IPrivateERC20
    function increaseAllowanceGT(
        address spender,
        gtUint256 addedValue
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        _increaseAllowance(_msgSender(), spender, addedValue);
    }

    /// @inheritdoc IPrivateERC20
    function decreaseAllowance(
        address spender,
        itUint256 calldata subtractedValue
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        gtUint256 gtSub = MpcCore.validateCiphertext(subtractedValue);
        _decreaseAllowance(_msgSender(), spender, gtSub);
    }

    /// @inheritdoc IPrivateERC20
    function decreaseAllowance(
        address spender,
        uint256 subtractedValue
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        _decreaseAllowance(_msgSender(), spender, MpcCore.setPublic256(subtractedValue));
    }

    /// @inheritdoc IPrivateERC20
    function decreaseAllowanceGT(
        address spender,
        gtUint256 subtractedValue
    ) public virtual override nonReentrant {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        _decreaseAllowance(_msgSender(), spender, subtractedValue);
    }

    /**
     * @dev See {IPrivateERC20-transferFrom}.
     *
     * Requirements:
     *
     * - `from` and `to` cannot be the zero address.
     * - `from` must have a balance of at least `value`.
     * - the caller must have allowance for ``from``'s tokens of at least
     * `value`.
     *
     * Order: (1) check allowance and revert if insufficient, (2) deduct via _spendAllowance, (3) _transfer.
     */
    /// @notice transferFrom with encrypted (itUint256) amount
    function transferFrom(
        address from,
        address to,
        itUint256 calldata value
    ) public virtual override nonReentrant {
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address spender = _msgSender();

        gtUint256 gtValue = MpcCore.validateCiphertext(value);

        {
            gtUint256 currentAllowance = _safeOnboard(_allowances[from][spender].ciphertext);
            gtBool maxAllowance = _isMaxAllowance(currentAllowance);
            gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, gtValue);
            require(
                MpcCore.decrypt(MpcCore.or(maxAllowance, MpcCore.not(inSufficientAllowance))),
                "ERC20: insufficient allowance"
            );
        }

        _spendAllowance(from, spender, gtValue);
    
        _transfer(from, to, gtValue);
    }

    /// @notice transferFrom with garbled-text (gtUint256) amount
    function transferFromGT(
        address from,
        address to,
        gtUint256 value
    ) public virtual override nonReentrant {
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address spender = _msgSender();

        {
            gtUint256 currentAllowance = _safeOnboard(_allowances[from][spender].ciphertext);
            gtBool maxAllowance = _isMaxAllowance(currentAllowance);
            gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, value);
            require(
                MpcCore.decrypt(MpcCore.or(maxAllowance, MpcCore.not(inSufficientAllowance))),
                "ERC20: insufficient allowance"
            );
        }

        _spendAllowance(from, spender, value);

        _transfer(from, to, value);
    }


    /// @notice transferFrom with plain public uint256 amount
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public virtual override nonReentrant {
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address spender = _msgSender();

        gtUint256 gtValue = MpcCore.setPublic256(value);

        {
            gtUint256 currentAllowance = _safeOnboard(_allowances[from][spender].ciphertext);
            gtBool maxAllowance = _isMaxAllowance(currentAllowance);
            gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, gtValue);
            require(
                MpcCore.decrypt(MpcCore.or(maxAllowance, MpcCore.not(inSufficientAllowance))),
                "ERC20: insufficient allowance"
            );
        }

        _spendAllowance(from, spender, gtValue);

        _transfer(from, to, gtValue);
    }

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Self-transfer (from == to) is not allowed and reverts.
     *
     * On success, emits a {Transfer} event via {_update}; on MPC transfer failure, {_update} reverts
     * and no event is emitted.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _transfer(
        address from,
        address to,
        gtUint256 value
    ) internal {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }

        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }

        if (from == to) {
            revert ERC20SelfTransferNotAllowed(from);
        }

        _update(from, to, value);
    }

    /**
     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`
     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding
     * this function.
     *
     * Storage and {Transfer} are updated only when the MPC operation succeeds (transfer success bit, or mint
     * add without overflow and within {supplyCap}). On failure, balances and aggregate supply are unchanged,
     * no event is emitted, and this function reverts so the failed operation does not succeed silently.
     */
    function _update(
        address from,
        address to,
        gtUint256 value
    ) internal virtual {
        gtUint256 newToBalance;
        gtUint256 valueTransferred = value;
        gtBool result;
        bool ok;

        if (from == address(0)) {
            gtUint256 currentBalance = _getBalance(to);
            gtBool balanceOverflow;
            (balanceOverflow, newToBalance) = MpcCore.checkedAddWithOverflowBit(
                currentBalance,
                value
            );
            gtBool balanceOk = MpcCore.not(balanceOverflow);

            gtUint256 totalSupply_ = _safeOnboard(_totalSupply);
            (gtBool supplyOverflow, gtUint256 newTotalSupply) = MpcCore.checkedAddWithOverflowBit(
                totalSupply_,
                value
            );
            gtBool supplyOk = MpcCore.not(supplyOverflow);
            gtBool withinCap = MpcCore.le(newTotalSupply, supplyCap());

            result = MpcCore.and(balanceOk, MpcCore.and(supplyOk, withinCap));
            ok = MpcCore.decrypt(result);
            if (ok) {
                _totalSupply = MpcCore.offBoard(newTotalSupply);

                _updateBalance(to, newToBalance);
            }
        } else {
            gtUint256 fromBalance = _getBalance(from);
            // Burn (`to == address(0)`): use canonical public zero as the sink balance. Do not read
            // `_balances[address(0)]` — that slot must never affect burn accounting if it were ever corrupted.
            gtUint256 toBalance = to == address(0)
                ? MpcCore.setPublic256(0)
                : _getBalance(to);

            gtUint256 newFromBalance;

            (newFromBalance, newToBalance, result) = MpcCore.transfer(
                fromBalance,
                toBalance,
                value
            );

            ok = MpcCore.decrypt(result);
            if (ok) {
                _updateBalance(from, newFromBalance);

                valueTransferred = MpcCore.sub(newToBalance, toBalance);

                if (to == address(0)) {
                    gtUint256 totalSupply_ = _safeOnboard(_totalSupply);

                    totalSupply_ = MpcCore.sub(totalSupply_, valueTransferred);

                    _totalSupply = MpcCore.offBoard(totalSupply_);
                } else {
                    _updateBalance(to, newToBalance);
                }
            }
        }

        if (ok) {
            // When minting or transferring to/from a smart contract (which has no AES key),
            // we must bypass offBoardToUser to prevent on-chain reverts.
            ctUint256 memory senderCt;
            address fromEnc = _getAccountEncryptionAddress(from);
            if (fromEnc != address(0)) {
                senderCt = MpcCore.offBoardToUser(valueTransferred, fromEnc);
            } else {
                senderCt = ctUint256({
                    ciphertextHigh: ctUint128.wrap(0),
                    ciphertextLow: ctUint128.wrap(0)
                });
            }

            ctUint256 memory receiverCt;
            address toEnc = _getAccountEncryptionAddress(to);
            if (toEnc != address(0)) {
                receiverCt = MpcCore.offBoardToUser(valueTransferred, toEnc);
            } else {
                receiverCt = ctUint256({
                    ciphertextHigh: ctUint128.wrap(0),
                    ciphertextLow: ctUint128.wrap(0)
                });
            }

            emit Transfer(from, to, senderCt, receiverCt);
        }
        require(MpcCore.decrypt(result), "ERC20: update failed");
    }

    /**
     * @dev Aggregate supply as a garbled value (on-boarded from storage ciphertext).
     *      Intended for subclasses that expose encrypted total supply to a designated party
     *      (e.g. via `MpcCore.offBoardToUser`) without putting plaintext aggregate supply in {totalSupply}.
     */
    function _getTotalSupplyGarbled() internal returns (gtUint256) {
        return _safeOnboard(_totalSupply);
    }

    function _getBalance(address account) internal returns (gtUint256) {
        ctUint256 memory ctBalance = _balances[account].ciphertext;

        return _safeOnboard(ctBalance);
    }

    function _getAccountEncryptionAddress(
        address account
    ) internal view returns (address) {
        if (account == address(0)) return address(0);

        address encryptionAddress = _accountEncryptionAddress[account];

        if (encryptionAddress == address(0)) {
            if (account.code.length > 0) {
                // Smart contracts don't have AES keys, so we return address(0)
                // as a signal to bypass encryption in offBoardToUser.
                return address(0);
            }
            encryptionAddress = account;
        }

        return encryptionAddress;
    }

    function _updateBalance(address account, gtUint256 balance) internal {
        address encryptionAddress = _getAccountEncryptionAddress(account);

        if (encryptionAddress == address(0)) {
            // Contract accounts have no AES key; store ciphertext only, no user reencryption.
            _balances[account].ciphertext = MpcCore.offBoard(balance);
            _balances[account].userCiphertext = ctUint256({
                ciphertextHigh: ctUint128.wrap(0),
                ciphertextLow: ctUint128.wrap(0)
            });
        } else {
            _balances[account] = MpcCore.offBoardCombined(
                balance,
                encryptionAddress
            );
        }
    }

    /**
     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
     * Relies on the `_update` mechanism
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _mint(address account, gtUint256 value) internal {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }

        _update(address(0), account, value);
    }

    /**
     * @dev Destroys a `value` amount of tokens from `account`, lowering the total supply.
     * Relies on the `_update` mechanism.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead
     */
    function _burn(address account, gtUint256 value) internal {
        if (account == address(0)) {
            revert ERC20InvalidSender(address(0));
        }

        _update(account, address(0), value);
    }

    /**
     * @dev Sets `value` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     *
     * Overrides to this logic should be done to the variant with an additional `bool emitEvent` argument.
     */

    /**
     * @dev If the new allowance is non-zero, requires the current allowance to be zero.
     *      Same mitigation as {approve(address,uint256)} / {ERC20UnsafeApprove} for the encrypted and GT approve paths.
     */
    function _requireSafeEncryptedApprove(
        address owner,
        address spender,
        gtUint256 gtNewValue
    ) internal {
        gtBool newIsZero = MpcCore.eq(gtNewValue, MpcCore.setPublic256(0));
        if (MpcCore.decrypt(newIsZero)) {
            return;
        }

        gtUint256 currentAllowance = _safeOnboard(
            _allowances[owner][spender].ciphertext
        );
        if (!MpcCore.decrypt(MpcCore.eq(currentAllowance, uint256(0)))) {
            revert ERC20UnsafeApprove();
        }
    }

    /**
     * @dev Atomically adds `added` to the current allowance. Reverts on overflow (mirrors
     *      ERC-20 reference behavior for `type(uint256).max + x`). Does not use
     *      {_requireSafeEncryptedApprove} — intended as the safe alternative to resetting via {approve}.
     */
    function _increaseAllowance(
        address owner,
        address spender,
        gtUint256 added
    ) internal {
        if (owner == address(0)) revert ERC20InvalidApprover(address(0));
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));

        gtUint256 currentAllowance = _safeOnboard(
            _allowances[owner][spender].ciphertext
        );
        (gtBool overflow, gtUint256 newAllowance) = MpcCore.checkedAddWithOverflowBit(
            currentAllowance,
            added
        );
        require(
            MpcCore.decrypt(MpcCore.not(overflow)),
            "ERC20: allowance overflow"
        );
        _approve(owner, spender, newAllowance);
    }

    /**
     * @dev Atomically subtracts `subtracted` from the current allowance. Reverts on underflow.
     */
    function _decreaseAllowance(
        address owner,
        address spender,
        gtUint256 subtracted
    ) internal {
        if (owner == address(0)) revert ERC20InvalidApprover(address(0));
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));

        gtUint256 currentAllowance = _safeOnboard(
            _allowances[owner][spender].ciphertext
        );
        (gtBool underflow, gtUint256 newAllowance) = MpcCore.checkedSubWithOverflowBit(
            currentAllowance,
            subtracted
        );
        require(
            MpcCore.decrypt(MpcCore.not(underflow)),
            "ERC20: insufficient allowance"
        );
        _approve(owner, spender, newAllowance);
    }

    function _approve(
        address owner,
        address spender,
        gtUint256 value
    ) internal {
        if (owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }

        if (spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }

        ctUint256 memory ciphertext = MpcCore.offBoard(value);

        address encryptionAddress = _getAccountEncryptionAddress(owner);

        ctUint256 memory ownerCiphertext;
        if (encryptionAddress != address(0)) {
            ownerCiphertext = MpcCore.offBoardToUser(value, encryptionAddress);
        } else {
            ownerCiphertext = ctUint256({
                ciphertextHigh: ctUint128.wrap(0),
                ciphertextLow: ctUint128.wrap(0)
            });
        }

        encryptionAddress = _getAccountEncryptionAddress(spender);

        ctUint256 memory spenderCiphertext;
        if (encryptionAddress != address(0)) {
            spenderCiphertext = MpcCore.offBoardToUser(
                value,
                encryptionAddress
            );
        } else {
            spenderCiphertext = ctUint256({
                ciphertextHigh: ctUint128.wrap(0),
                ciphertextLow: ctUint128.wrap(0)
            });
        }

        _allowances[owner][spender] = Allowance(
            ciphertext,
            ownerCiphertext,
            spenderCiphertext
        );

        emit Approval(owner, spender, ownerCiphertext, spenderCiphertext);
    }

    /**
     * @dev Updates `owner` s allowance for `spender` based on spent `value`.
     *
     * Does not decrease the allowance value in case of infinite allowance.
     * Does not decrease the allowance if not enough allowance is available.
     *
     */
    /**
     * @dev Unlimited allowance: semantic equality to `type(uint256).max` via secret-vs-public
     *      `eq` (MPC RHS_PUBLIC). Using this instead of `eq(allowance, setPublic256(max))` ensures
     *      any valid garbled encoding of max is recognized, not only one canonical pair.
     */
    function _isMaxAllowance(gtUint256 gtAllowance) internal returns (gtBool) {
        return MpcCore.eq(gtAllowance, MAX_UINT_256);
    }

    function _spendAllowance(
        address owner,
        address spender,
        gtUint256 value
    ) internal virtual {
        gtUint256 currentAllowance = _safeOnboard(
            _allowances[owner][spender].ciphertext
        );

        gtBool maxAllowance = _isMaxAllowance(currentAllowance);
        gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, value);

        gtUint256 newAllowance = MpcCore.mux(
            // If allowance is infinite, do not decrease it.
            // If allowance is insufficient (should be prevented by transferFrom checks), do not decrease it.
            MpcCore.or(maxAllowance, inSufficientAllowance),
            currentAllowance,
            MpcCore.sub(currentAllowance, value)
        );

        _approve(owner, spender, newAllowance);
    }

    /// @dev EVM-uninitialized or fully cleared `ctUint256` storage reads as both limbs zero.
    function _isCanonicalEmptyCtUint256(
        ctUint256 memory ct
    ) private pure returns (bool) {
        return
            ctUint128.unwrap(ct.ciphertextHigh) == 0 &&
            ctUint128.unwrap(ct.ciphertextLow) == 0;
    }

    /**
     * @dev Converts persisted `ctUint256` into garbled `gtUint256` for MPC operations.
     *
     * **Canonical zero:** Storage that has never been written, or reads as all-zero limbs, is
     * treated as semantic zero via `MpcCore.setPublic256(0)` without `MpcCore.onBoard`, to avoid a
     * precompile round-trip on empty balances/allowances/supply. Any non–all-zero encoding is
     * onboarded with `MpcCore.onBoard`.
     *
     * Invariant: values persisted by this contract come from `MpcCore.offBoard` after successful MPC
     * updates, so normal state is consistent with the precompile. Subclasses or integrations must not
     * inject arbitrary ciphertext into these slots unless it matches MPC encoding expectations.
     */
    function _safeOnboard(ctUint256 memory value) internal returns (gtUint256) {
        if (_isCanonicalEmptyCtUint256(value)) {
            return MpcCore.setPublic256(0);
        }
        return MpcCore.onBoard(value);
    }
}
