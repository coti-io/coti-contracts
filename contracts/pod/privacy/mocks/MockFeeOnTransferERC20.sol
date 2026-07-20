// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Test ERC20 that burns a configurable basis-point fee on every `transferFrom`, simulating a
///      fee-on-transfer / rebasing underlying so the recipient always receives less than the requested amount.
contract MockFeeOnTransferERC20 is ERC20 {
    uint256 internal constant FEE_DIVISOR = 10_000;

    uint8 private immutable _decimals;
    /// @notice Fee taken on `transferFrom`, in basis points (100 = 1%).
    uint256 public feeBps;

    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint256 feeBps_) ERC20(name_, symbol_) {
        _decimals = decimals_;
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setFeeBps(uint256 feeBps_) external {
        feeBps = feeBps_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    /// @dev Only `transferFrom` charges the fee, matching real fee-on-transfer tokens that tax every move
    ///      (the portal always calls `transferFrom`, never `transfer`).
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        uint256 fee = (amount * feeBps) / FEE_DIVISOR;
        _burn(from, fee);
        _transfer(from, to, amount - fee);
        return true;
    }
}
