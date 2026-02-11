// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IPrivateERC20, ITokenReceiver} from "./IPrivateERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@coti-io/coti-contracts/contracts/utils/mpc/MpcCore.sol";


/*
THIS IS THE 256 BIT VERSION OF PRIVATE ERC20.

Key Features:
- Full uint256 support (no scaling factors)
- AccessControl (for Bridge Integrations)
- ERC165 Support - Tokens Discoverability
- Payable Tokens with TransferAndCall (ERC677-like callback pattern)
- Encrypted Operations (Mint, Burn, Transfer, Approve)
*/

abstract contract PrivateERC20 is Context, ERC165, IPrivateERC20, AccessControl {
    uint256 private constant MAX_UINT_256 = type(uint256).max;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    mapping(address account => address) private _accountEncryptionAddress;

    mapping(address account => utUint256) private _balances;

    mapping(address account => mapping(address spender => Allowance)) private _allowances;

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
     * @dev Sets the values for {name} and {symbol}.
     *
     * All two of these values are immutable: they can only be set once during
     * construction.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
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
     * @dev See {IPrivateERC20-totalSupply}.
     */
    function totalSupply() public view virtual returns (uint256) {
        return 0;
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        _mint(to, gtAmount);
    }

    function burn(uint256 amount) public {
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        _burn(msg.sender, gtAmount);
    }

    function burn(address from, uint256 amount) public onlyRole(MINTER_ROLE) {
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        _burn(from, gtAmount);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        _transfer(msg.sender, to, gtAmount);
        return true;
    }

    function transferAndCall(address to, uint256 amount, bytes calldata data) public virtual returns (bool) {
        gtUint256 memory gtAmount = MpcCore.setPublic256(amount);
        gtBool success = _transfer(msg.sender, to, gtAmount);
        require(MpcCore.decrypt(success), "Transfer failed");

        if (to.code.length > 0) {
            require(ITokenReceiver(to).onTokenReceived(msg.sender, amount, data), "Callback failed");
        }
        return true;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControl, ERC165) returns (bool) {
        return interfaceId == type(IPrivateERC20).interfaceId || super.supportsInterface(interfaceId);
    }

    function accountEncryptionAddress(address account) public view returns (address) {
        return _accountEncryptionAddress[account];
    } 

    /**
     * @dev See {IPrivateERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual returns (ctUint256 memory) {
        return _balances[account].userCiphertext;
    }

    /**
     * @dev See {IPrivateERC20-balanceOf}.
     */
    function balanceOf() public virtual returns (gtUint256 memory) {
        return _getBalance(_msgSender());
    }

    /**
     * @dev See {IPrivateERC20-setAccountEncryptionAddress}.
     * 
     * NOTE: This will not reencrypt your allowances until they are changed
     */
    function setAccountEncryptionAddress(address offBoardAddress) public virtual returns (bool) {
        gtUint256 memory gtBalance = _getBalance(_msgSender());

        _accountEncryptionAddress[_msgSender()] = offBoardAddress;

        _balances[_msgSender()].userCiphertext = MpcCore.offBoardToUser(gtBalance, offBoardAddress);

        return true;
    }
    
    /**
     * @dev See {IPrivateERC20-transfer}.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `value`.
     */
    function transfer(address to, itUint256 calldata value) public virtual returns (gtBool) {
        address owner = _msgSender();

        gtUint256 memory gtValue = MpcCore.validateCiphertext(value);

        return _transfer(owner, to, gtValue);
    }

    /**
     * @dev See {IPrivateERC20-transfer}.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `value`.
     */
    function transfer(address to, gtUint256 memory value) public virtual returns (gtBool) {
        address owner = _msgSender();

        return _transfer(owner, to, value);
    }

    /**
     * @dev See {IPrivateERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual returns (Allowance memory) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IPrivateERC20-allowance}.
     */
    function allowance(address account, bool isSpender) public virtual returns (gtUint256 memory) {
        if (isSpender) {
            return _safeOnboard(_allowances[_msgSender()][account].ciphertext);
        } else {
            return _safeOnboard(_allowances[account][_msgSender()].ciphertext);
        }
    }

    function reencryptAllowance(address account, bool isSpender) public virtual returns (bool) {
        address encryptionAddress = _getAccountEncryptionAddress(_msgSender());

        if (isSpender) {
            Allowance storage allowance_ = _allowances[_msgSender()][account];

            allowance_.ownerCiphertext = MpcCore.offBoardToUser(
                _safeOnboard(allowance_.ciphertext),
                encryptionAddress
            );
        } else {
            Allowance storage allowance_ = _allowances[account][_msgSender()];

            allowance_.spenderCiphertext = MpcCore.offBoardToUser(
                _safeOnboard(allowance_.ciphertext),
                encryptionAddress
            );
        }

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
    function approve(address spender, itUint256 calldata value) public virtual returns (bool) {
        address owner = _msgSender();

        gtUint256 memory gtValue = MpcCore.validateCiphertext(value);

        _approve(owner, spender, gtValue);

        return true;
    }

    /**
     * @dev See {IPrivateERC20-approve}.
     *
     * NOTE: If `value` is the maximum `gtUint256`, the allowance is not updated on
     * `transferFrom`. This is semantically equivalent to an infinite approval.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, gtUint256 memory value) public virtual returns (bool) {
        address owner = _msgSender();

        _approve(owner, spender, value);

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
     */
    function transferFrom(address from, address to, itUint256 calldata value) public virtual returns (gtBool) {
        address spender = _msgSender();

        gtUint256 memory gtValue = MpcCore.validateCiphertext(value);

        _spendAllowance(from, spender, gtValue);

        return _transfer(from, to, gtValue);
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
     */
    function transferFrom(address from, address to, gtUint256 memory value) public virtual returns (gtBool) {
        address spender = _msgSender();

        _spendAllowance(from, spender, value);

        return _transfer(from, to, value);
    }
    
    /**
     * @dev Moves a `value` amount of tokens from `from` to `to`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _transfer(address from, address to, gtUint256 memory value) internal returns (gtBool) {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }

        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }

        return _update(from, to, value);
    }
    
    /**
     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`
     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding
     * this function.
     *
     * Emits a {Transfer} event.
     */
    function _update(address from, address to, gtUint256 memory value) internal virtual returns (gtBool) {
        gtUint256 memory newToBalance;
        gtUint256 memory valueTransferred = value;
        gtBool result = MpcCore.setPublic(true);

        if (from == address(0)) {
            gtUint256 memory totalSupply_ = _safeOnboard(_totalSupply);

            totalSupply_ = MpcCore.add(totalSupply_, value);

            _totalSupply = MpcCore.offBoard(totalSupply_);

            gtUint256 memory currentBalance = _getBalance(to);

            newToBalance = MpcCore.add(currentBalance, value);
        } else {
            gtUint256 memory fromBalance = _getBalance(from);
            gtUint256 memory toBalance = _getBalance(to);

            gtUint256 memory newFromBalance;

            (newFromBalance, newToBalance, result) = MpcCore.transfer(fromBalance, toBalance, value);

            _updateBalance(from, newFromBalance);

            valueTransferred = MpcCore.sub(newToBalance, toBalance);
        }

        if (to == address(0)) {
            gtUint256 memory totalSupply_ = _safeOnboard(_totalSupply);

            totalSupply_ = MpcCore.sub(totalSupply_, valueTransferred);

            _totalSupply = MpcCore.offBoard(totalSupply_);
        } else {
            _updateBalance(to, newToBalance);
        }
        
        emit Transfer(
            from,
            to,
            MpcCore.offBoardToUser(valueTransferred, from),
            MpcCore.offBoardToUser(valueTransferred, to)
        );

        return result;
    }

    function _getBalance(address account) internal returns (gtUint256 memory) {
        ctUint256 memory ctBalance = _balances[account].ciphertext;

        return _safeOnboard(ctBalance);
    }

    function _getAccountEncryptionAddress(address account) internal view returns (address) {
        address encryptionAddress = _accountEncryptionAddress[account];

        if (encryptionAddress == address(0)) {
            encryptionAddress = account;
        }

        return encryptionAddress;
    }

    function _updateBalance(address account, gtUint256 memory balance) internal {
        address encryptionAddress = _getAccountEncryptionAddress(account);

        _balances[account] = MpcCore.offBoardCombined(balance, encryptionAddress);
    }
    
    /**
     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
     * Relies on the `_update` mechanism
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _mint(address account, gtUint256 memory value) internal returns (gtBool) {
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
    function _burn(address account, gtUint256 memory value) internal returns (gtBool) {
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
    function _approve(address owner, address spender, gtUint256 memory value) internal {
        if (owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }

        if (spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }

        ctUint256 memory ciphertext = MpcCore.offBoard(value);

        address encryptionAddress = _getAccountEncryptionAddress(owner);

        ctUint256 memory ownerCiphertext = MpcCore.offBoardToUser(value, encryptionAddress);

        encryptionAddress = _getAccountEncryptionAddress(spender);

        ctUint256 memory spenderCiphertext = MpcCore.offBoardToUser(value, encryptionAddress);

        _allowances[owner][spender] = Allowance(ciphertext, ownerCiphertext, spenderCiphertext);

        emit Approval(owner, spender, ownerCiphertext, spenderCiphertext);
    }

    /**
     * @dev Updates `owner` s allowance for `spender` based on spent `value`.
     *
     * Does not decrease the allowance value in case of infinite allowance.
     * Does not decrease the allowance if not enough allowance is available.
     *
     */
    function _spendAllowance(address owner, address spender, gtUint256 memory value) internal virtual {
        gtUint256 memory currentBalance = _safeOnboard(_balances[owner].ciphertext);
        gtUint256 memory currentAllowance = _safeOnboard(_allowances[owner][spender].ciphertext);

        gtBool maxAllowance = MpcCore.eq(currentAllowance, MpcCore.setPublic256(MAX_UINT_256));
        gtBool insufficientBalance = MpcCore.lt(currentBalance, value);
        gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, value);

        gtUint256 memory newAllowance = MpcCore.mux(
            MpcCore.or(maxAllowance, MpcCore.or(insufficientBalance, inSufficientAllowance)),
            MpcCore.sub(currentAllowance, value),
            currentAllowance
        );

        _approve(owner, spender, newAllowance);
    }

    function _safeOnboard(ctUint256 memory value) internal returns (gtUint256 memory) {
        if (
            ctUint64.unwrap(value.high.high) == 0 &&
            ctUint64.unwrap(value.high.low) == 0 &&
            ctUint64.unwrap(value.low.high) == 0 &&
            ctUint64.unwrap(value.low.low) == 0
        ) {
            return MpcCore.setPublic256(0);
        }

        return MpcCore.onBoard(value);
    }
}