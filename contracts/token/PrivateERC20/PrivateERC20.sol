// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "./IPrivateERC20.sol";
import "../../utils/mpc/MpcCore.sol";
import "./IERC1363Receiver.sol";

/**
 * @title PrivateERC20_ERC7984
 * @dev An improved PrivateERC20 implementation incorporating ERC-7984 features:
 *      1. Introspection (ERC-165)
 *      2. Encrypted Total Supply (Confidential Visibility)
 *      3. ERC-1363 Callbacks (Single-Transaction DeFi)
 *      
 *      @notice Inherits from Context to support meta-transactions (via _msgSender())
 */
abstract contract PrivateERC20 is Context, IPrivateERC20, ERC165 {
    uint64 private constant MAX_UINT_64 = type(uint64).max;

    mapping(address account => address) private _accountEncryptionAddress;

    mapping(address account => utUint64) private _balances;

    mapping(address account => mapping(address spender => Allowance)) private _allowances;

    // Internal to allow child contracts to expose reading functions (Confidential Total Supply)
    ctUint64 internal _totalSupply;

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

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    // =============================================================
    // 1. Introspection (ERC-165)
    // =============================================================

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IPrivateERC20).interfaceId || super.supportsInterface(interfaceId);
    }

    // =============================================================
    // 2. Encrypted Total Supply (Confidential Visibility)
    // =============================================================

    /**
     * @dev Returns the total supply as a valid ciphertext (ctUint64).
     */
    function confidentialTotalSupply() public view virtual returns (ctUint64) {
        return _totalSupply;
    }

    // =============================================================
    // Standard PrivateERC20 Functions 
    // =============================================================

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual returns (uint8) {
        return 6;
    }

    // Public view returns 0 (Opaque)
    function totalSupply() public view virtual returns (uint256) {
        return 0;
    }

    function accountEncryptionAddress(address account) public view returns (address) {
        return _accountEncryptionAddress[account];
    } 

    function balanceOf(address account) public view virtual returns (ctUint64) {
        return _balances[account].userCiphertext;
    }

    function balanceOf() public virtual returns (gtUint64) {
        return _getBalance(_msgSender());
    }

    function setAccountEncryptionAddress(address offBoardAddress) public virtual returns (bool) {
        gtUint64 gtBalance = _getBalance(_msgSender());
        _accountEncryptionAddress[_msgSender()] = offBoardAddress;
        _balances[_msgSender()].userCiphertext = MpcCore.offBoardToUser(gtBalance, offBoardAddress);
        return true;
    }
    
    function transfer(address to, itUint64 calldata value) public virtual returns (gtBool) {
        address owner = _msgSender();
        gtUint64 gtValue = MpcCore.validateCiphertext(value);
        return _transfer(owner, to, gtValue);
    }

    function transfer(address to, gtUint64 value) public virtual returns (gtBool) {
        address owner = _msgSender();
        return _transfer(owner, to, value);
    }

    function allowance(address owner, address spender) public view virtual returns (Allowance memory) {
        return _allowances[owner][spender];
    }

    function allowance(address account, bool isSpender) public virtual returns (gtUint64) {
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

    function approve(address spender, itUint64 calldata value) public virtual returns (bool) {
        address owner = _msgSender();
        gtUint64 gtValue = MpcCore.validateCiphertext(value);
        _approve(owner, spender, gtValue);
        return true;
    }

    function approve(address spender, gtUint64 value) public virtual returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, value);
        return true;
    }

    function transferFrom(address from, address to, itUint64 calldata value) public virtual returns (gtBool) {
        address spender = _msgSender();
        gtUint64 gtValue = MpcCore.validateCiphertext(value);
        _spendAllowance(from, spender, gtValue);
        return _transfer(from, to, gtValue);
    }
    
    function transferFrom(address from, address to, gtUint64 value) public virtual returns (gtBool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        return _transfer(from, to, value);
    }
    
    function _transfer(address from, address to, gtUint64 value) internal returns (gtBool) {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        return _update(from, to, value);
    }
    
    function _update(address from, address to, gtUint64 value) internal virtual returns (gtBool) {
        gtUint64 newToBalance;
        gtUint64 valueTransferred = value;
        gtBool result = MpcCore.setPublic(true);

        if (from == address(0)) {
            gtUint64 totalSupply_ = _safeOnboard(_totalSupply);
            totalSupply_ = MpcCore.add(totalSupply_, value);
            _totalSupply = MpcCore.offBoard(totalSupply_);

            gtUint64 currentBalance = _getBalance(to);
            newToBalance = MpcCore.add(currentBalance, value);
        } else {
            gtUint64 fromBalance = _getBalance(from);
            gtUint64 toBalance = _getBalance(to);
            gtUint64 newFromBalance;

            (newFromBalance, newToBalance, result) = MpcCore.transfer(fromBalance, toBalance, value);
            _updateBalance(from, newFromBalance);
            valueTransferred = MpcCore.sub(newToBalance, toBalance);
        }

        if (to == address(0)) {
            gtUint64 totalSupply_ = _safeOnboard(_totalSupply);
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

    function _getBalance(address account) internal returns (gtUint64) {
        ctUint64 ctBalance = _balances[account].ciphertext;
        return _safeOnboard(ctBalance);
    }

    function _getAccountEncryptionAddress(address account) internal view returns (address) {
        address encryptionAddress = _accountEncryptionAddress[account];
        if (encryptionAddress == address(0)) {
            encryptionAddress = account;
        }
        return encryptionAddress;
    }

    function _updateBalance(address account, gtUint64 balance) internal {
        address encryptionAddress = _getAccountEncryptionAddress(account);
        _balances[account] = MpcCore.offBoardCombined(balance, encryptionAddress);
    }
    
    function _mint(address account, gtUint64 value) internal returns (gtBool) {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        return _update(address(0), account, value);
    }

    function _burn(address account, gtUint64 value) internal returns (gtBool) {
        if (account == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        return _update(account, address(0), value);
    }

    function _approve(address owner, address spender, gtUint64 value) internal {
        if (owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }
        if (spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }

        ctUint64 ciphertext = MpcCore.offBoard(value);
        address encryptionAddress = _getAccountEncryptionAddress(owner);
        ctUint64 ownerCiphertext = MpcCore.offBoardToUser(value, encryptionAddress);
        encryptionAddress = _getAccountEncryptionAddress(spender);
        ctUint64 spenderCiphertext = MpcCore.offBoardToUser(value, encryptionAddress);

        _allowances[owner][spender] = Allowance(ciphertext, ownerCiphertext, spenderCiphertext);
        emit Approval(owner, spender, ownerCiphertext, spenderCiphertext);
    }

    function _spendAllowance(address owner, address spender, gtUint64 value) internal virtual {
        gtUint64 currentBalance = _safeOnboard(_balances[owner].ciphertext);
        gtUint64 currentAllowance = _safeOnboard(_allowances[owner][spender].ciphertext);

        gtBool maxAllowance = MpcCore.eq(currentAllowance, MpcCore.setPublic64(MAX_UINT_64));
        gtBool insufficientBalance = MpcCore.lt(currentBalance, value);
        gtBool inSufficientAllowance = MpcCore.lt(currentAllowance, value);

        gtUint64 newAllowance = MpcCore.mux(
            MpcCore.or(maxAllowance, MpcCore.or(insufficientBalance, inSufficientAllowance)),
            MpcCore.sub(currentAllowance, value),
            currentAllowance
        );

        _approve(owner, spender, newAllowance);
    }

    function _safeOnboard(ctUint64 value) internal returns (gtUint64) {
        if (ctUint64.unwrap(value) == 0) {
            return MpcCore.setPublic64(0);
        }
        return MpcCore.onBoard(value);
    }

    // =============================================================
    // 3. ERC-1363 Callbacks Implementation
    // =============================================================

    function _transferAndCall(address from, address to, gtUint64 value, bytes calldata data) internal returns (gtBool) {
        // 1. Perform standard encrypted transfer
        gtBool success = _transfer(from, to, value);

        // 2. Optimistic callback: Call the recipient if it is a contract
        if (to.code.length > 0) {
            try IERC1363Receiver(to).onTransferReceived(_msgSender(), from, 0, data) returns (bytes4 retval) {
                require(retval == IERC1363Receiver.onTransferReceived.selector, "TransferAndCall: Invalid callback return");
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("TransferAndCall: Transfer to non-ERC1363Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        }

        return success;
    }

    function transferAndCall(address to, itUint64 calldata value, bytes calldata data) public virtual returns (gtBool) {
        gtUint64 gtValue = MpcCore.validateCiphertext(value);
        return _transferAndCall(_msgSender(), to, gtValue, data);
    }
    
    function transferAndCall(address to, uint64 value, bytes calldata data) public virtual returns (gtBool) {
        gtUint64 gtValue = MpcCore.setPublic64(value);
        return _transferAndCall(_msgSender(), to, gtValue, data);
    }
}
