// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../PodERC20.sol";

/// @title PodERC20Burnable
/// @notice OpenZeppelin-style extension: public burn entry points delegating to {PodERC20._burn} / {_burnPublic}.
/// @dev Mirrors {ERC20Burnable}: base keeps internal burn machinery; this contract only exposes `burn`.
///      Implements the full {IPodERC20} surface (including {burn}) without an explicit `is IPodERC20` clause
///      to avoid duplicate-base override requirements against {PodERC20}'s concrete externals.
abstract contract PodERC20Burnable is PodERC20 {
    /// @dev See {IPodERC20}.
    function burn(itUint256 calldata value, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _burn(msg.sender, value, msg.value, callbackFeeLocalWei);
    }

    /// @dev See {IPodERC20}.
    function burn(uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        return _burnPublic(msg.sender, amount, msg.value, callbackFeeLocalWei);
    }
}
