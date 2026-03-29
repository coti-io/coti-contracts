// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IPrivateERC20} from "./IPrivateERC20.sol";
import {ITokenReceiver} from "./ITokenReceiver.sol";
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

Trust assumptions (deploy only when these hold):
- Deploy only on chains where the MPC precompile at address(0x64) is part of the trusted base.
  The precompile is correct and non-malicious; all balances/transfers depend on it. If the chain
  allows precompile upgrades, consider monitoring or circuit-breakers.
- MINTER_ROLE must only pass valid amounts to mint/mintGt/mint(itUint256). If the MPC layer
  enforces bounds or validity, that dependency applies.
- Minting is bounded by {supplyCap} (override in concrete tokens like {decimals}); enforced in {_update}.
- Encrypted/GT variants (transfer, burn, mint with itUint256/gtUint256) return success as gtBool
  and do not revert; callers must check or decrypt the return value. Integrators should use
  helpers that revert on failure when appropriate.
- Gas: multiple precompile calls per transfer/approve; no unbounded loops. Document expected
  gas ranges for common operations if needed for integrators.
- Reentrancy: balance/allowance-changing entry points use nonReentrant so a transferAndCall
  receiver cannot nest transferFrom/transfer/approve/mint/burn in the same transaction.
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
     * @dev Maximum aggregate supply that may exist from minting (enforced in {_update} against encrypted total).
     *      Override in concrete tokens with a fixed cap; default is `type(uint256).max` (bounded only by uint256 overflow checks).
     */
    function supplyCap() public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /**
     * @dev See {IPrivateERC20-totalSupply}.
     *      For privacy, always returns 0; aggregate supply is not exposed on-chain by default so
     *      holder amounts stay private. Integrators: use for display only; do not rely on this for
     *      supply accounting.
     *
     *      Dev note: a concrete implementation may choose to extend this pattern—for example by
     *      maintaining an encrypted total and exposing it via reencryption to a designated owner or
     *      role—if they wish to track total supply off the public path. That is not enabled here
     *      by default.
     *
     *      For the configured mint ceiling, see {supplyCap}; minting enforces it against the encrypted total in storage.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return 0;
    }

    function mint(
        address to,
        uint256 amount
    ) public virtual override onlyRole(MINTER_ROLE) nonReentrant returns (bool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        gtUint256 gtAmount = MpcCore.setPublic256(amount);
        gtBool success = _mint(to, gtAmount);
        require(MpcCore.decrypt(success), "ERC20: mint failed");

        return true;
    }

    /**
     * @dev Mint an already-garbled amount without re-wrapping.
     * Intended for contract-to-contract flows that already hold a gtUint256.
     * Trust: MINTER_ROLE must only pass valid amounts. Does not revert on MPC failure;
     * returns gtBool — callers must check or decrypt.
     */
    function mintGt(
        address to,
        gtUint256 gtAmount
    ) public virtual onlyRole(MINTER_ROLE) nonReentrant returns (gtBool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        return _mint(to, gtAmount);
    }

    /**
     * @dev Mint with encrypted (itUint256) amount.
     * Trust: MINTER_ROLE must only pass valid amounts. Does not revert on MPC failure;
     * returns gtBool — callers must check or decrypt.
     */
    function mint(
        address to,
        itUint256 calldata amount
    ) public virtual override onlyRole(MINTER_ROLE) nonReentrant returns (gtBool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        return _mint(to, gtAmount);
    }

    function burn(uint256 amount) public virtual override nonReentrant returns (bool) {
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        gtUint256 gtAmount = MpcCore.setPublic256(amount);
        gtBool success = _burn(_msgSender(), gtAmount);
        require(MpcCore.decrypt(success), "ERC20: burn failed");

        return true;
    }

    /**
     * @dev Burn an already-garbled amount without re-wrapping.
     * Intended for contract-to-contract flows that already hold a gtUint256.
     * Returns encrypted success; callers must check or decrypt. Does not revert on failure.
     */
    function burnGt(gtUint256 gtAmount) public virtual nonReentrant returns (gtBool) {
        return _burn(_msgSender(), gtAmount);
    }

    /// @dev Does not revert on failure; returns encrypted boolean. Callers must check or decrypt.
    function burn(itUint256 calldata amount) public virtual override nonReentrant returns (gtBool) {
        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        return _burn(_msgSender(), gtAmount);
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
    ) public virtual override nonReentrant returns (bool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (to.code.length == 0) revert TransferAndCallRequiresContract(to);
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();

        gtUint256 gtAmount = MpcCore.setPublic256(amount);
        address sender = _msgSender();
        gtBool success = _transfer(sender, to, gtAmount);
        bool ok = MpcCore.decrypt(success);
        require(ok, "Transfer failed");

        require(
            ITokenReceiver(to).onTokenReceived(sender, amount, data),
            "Callback failed"
        );
        return ok;
    }

    /**
     * @dev Transfers encrypted amount to `to` then calls onTokenReceived(to, 0, data).
     *      For privacy, the callback receives 0 as the amount argument; the actual amount is not passed.
     *      Only use with trusted receivers; see {transferAndCall(address,uint256,bytes)} for reentrancy scope.
     */
    function transferAndCall(
        address to,
        itUint256 calldata amount,
        bytes calldata data
    ) public virtual override nonReentrant returns (gtBool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (to.code.length == 0) revert TransferAndCallRequiresContract(to);

        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        address sender = _msgSender();
        gtBool success = _transfer(sender, to, gtAmount);
        require(MpcCore.decrypt(success), "Transfer failed");

        require(
            ITokenReceiver(to).onTokenReceived(sender, 0, data),
            "Callback failed"
        );
        return success;
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
     * Does not revert on failure; returns encrypted boolean. Callers must check or decrypt.
     */
    /// @notice Transfer with encrypted (itUint256) amount
    function transfer(
        address to,
        itUint256 calldata value
    ) public virtual override nonReentrant returns (gtBool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address owner = _msgSender();

        gtUint256 gtValue = MpcCore.validateCiphertext(value);

        return _transfer(owner, to, gtValue);
    }

    /// @notice Transfer with garbled-text (gtUint256) amount. Does not revert on failure; returns encrypted boolean.
    function transferGT(
        address to,
        gtUint256 value
    ) public virtual override nonReentrant returns (gtBool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address owner = _msgSender();

        return _transfer(owner, to, value);
    }

    /// @notice Transfer with plain public uint256 amount
    function transfer(
        address to,
        uint256 value
    ) public virtual override nonReentrant returns (bool) {
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        address owner = _msgSender();

        gtUint256 gtValue = MpcCore.setPublic256(value);

        gtBool success = _transfer(owner, to, gtValue);
        require(MpcCore.decrypt(success), "ERC20: transfer failed");

        return true;
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
    ) public virtual nonReentrant returns (bool) {
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

        return true;
    }

    /**
     * @dev See {IPrivateERC20-approve}.
     *
     * NOTE: If `value` is the maximum `itUint256`, the allowance is not updated on
     * `transferFrom`. This is semantically equivalent to an infinite approval.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    /// @notice Approve with encrypted (itUint256) amount
    function approve(
        address spender,
        itUint256 calldata value
    ) public virtual override nonReentrant returns (bool) {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        address owner = _msgSender();

        gtUint256 gtValue = MpcCore.validateCiphertext(value);

        _approve(owner, spender, gtValue);

        return true;
    }

    /// @notice Approve with garbled-text (gtUint256) amount
    function approveGT(
        address spender,
        gtUint256 value
    ) public virtual override nonReentrant returns (bool) {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        address owner = _msgSender();

        _approve(owner, spender, value);

        return true;
    }

    /// @notice Approve with plain public uint256 amount
    function approve(
        address spender,
        uint256 value
    ) public virtual override nonReentrant returns (bool) {
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

        return true;
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
    ) public virtual override nonReentrant returns (gtBool) {
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address spender = _msgSender();

        gtUint256 gtValue = MpcCore.validateCiphertext(value);

        {
            gtUint256 currentAllowance = _safeOnboard(_allowances[from][spender].ciphertext);
            gtBool maxAllowance = MpcCore.eq(currentAllowance, MpcCore.setPublic256(MAX_UINT_256));
            gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, gtValue);
            require(
                MpcCore.decrypt(MpcCore.or(maxAllowance, MpcCore.not(inSufficientAllowance))),
                "ERC20: insufficient allowance"
            );
        }

        _spendAllowance(from, spender, gtValue);

        gtBool success = _transfer(from, to, gtValue);
        require(MpcCore.decrypt(success), "ERC20: transfer failed");

        return success;
    }

    /// @notice transferFrom with garbled-text (gtUint256) amount
    function transferFromGT(
        address from,
        address to,
        gtUint256 value
    ) public virtual override nonReentrant returns (gtBool) {
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address spender = _msgSender();

        {
            gtUint256 currentAllowance = _safeOnboard(_allowances[from][spender].ciphertext);
            gtBool maxAllowance = MpcCore.eq(currentAllowance, MpcCore.setPublic256(MAX_UINT_256));
            gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, value);
            require(
                MpcCore.decrypt(MpcCore.or(maxAllowance, MpcCore.not(inSufficientAllowance))),
                "ERC20: insufficient allowance"
            );
        }

        _spendAllowance(from, spender, value);

        gtBool success = _transfer(from, to, value);
        require(MpcCore.decrypt(success), "ERC20: transfer failed");

        return success;
    }


    /// @notice transferFrom with plain public uint256 amount
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public virtual override nonReentrant returns (bool) {
        if (!publicAmountsEnabled) revert PublicAmountsDisabled();
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0)) revert ERC20InvalidReceiver(address(0));
        address spender = _msgSender();

        gtUint256 gtValue = MpcCore.setPublic256(value);

        {
            gtUint256 currentAllowance = _safeOnboard(_allowances[from][spender].ciphertext);
            gtBool maxAllowance = MpcCore.eq(currentAllowance, MpcCore.setPublic256(MAX_UINT_256));
            gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, gtValue);
            require(
                MpcCore.decrypt(MpcCore.or(maxAllowance, MpcCore.not(inSufficientAllowance))),
                "ERC20: insufficient allowance"
            );
        }

        _spendAllowance(from, spender, gtValue);

        gtBool success = _transfer(from, to, gtValue);
        require(MpcCore.decrypt(success), "ERC20: transfer failed");

        return true;
    }

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Self-transfer (from == to) is not allowed and reverts.
     *
     * On success, emits a {Transfer} event via {_update}; on MPC transfer failure, no event is emitted.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _transfer(
        address from,
        address to,
        gtUint256 value
    ) internal returns (gtBool) {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }

        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }

        if (from == to) {
            revert ERC20SelfTransferNotAllowed(from);
        }

        return _update(from, to, value);
    }

    /**
     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`
     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding
     * this function.
     *
     * Storage and {Transfer} are updated only when the MPC operation succeeds (transfer success bit, or mint
     * add without overflow and within {supplyCap}). On failure, balances and aggregate supply are unchanged and no event is emitted.
     */
    function _update(
        address from,
        address to,
        gtUint256 value
    ) internal virtual returns (gtBool) {
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
            gtUint256 toBalance = _getBalance(to);

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

        return result;
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
    function _mint(address account, gtUint256 value) internal returns (gtBool) {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }

        return _update(address(0), account, value);
    }

    /**
     * @dev Destroys a `value` amount of tokens from `account`, lowering the total supply.
     * Relies on the `_update` mechanism.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead
     */
    function _burn(address account, gtUint256 value) internal returns (gtBool) {
        if (account == address(0)) {
            revert ERC20InvalidSender(address(0));
        }

        return _update(account, address(0), value);
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
    function _spendAllowance(
        address owner,
        address spender,
        gtUint256 value
    ) internal virtual {
        gtUint256 currentAllowance = _safeOnboard(
            _allowances[owner][spender].ciphertext
        );

        gtBool maxAllowance = MpcCore.eq(
            currentAllowance,
            MpcCore.setPublic256(MAX_UINT_256)
        );
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

    function _safeOnboard(ctUint256 memory value) internal returns (gtUint256) {
        // If both 128-bit ciphertext halves are zero, treat as canonical encoding of zero (public 0).
        if (
            ctUint128.unwrap(value.ciphertextHigh) == 0 &&
            ctUint128.unwrap(value.ciphertextLow) == 0
        ) {
            return MpcCore.setPublic256(0);
        }

        return MpcCore.onBoard(value);
    }
}
