// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "./PodErc20Mintable.sol";

/// @title PodErc20MintableInitializable
/// @notice Clone-friendly {PodErc20Mintable}; the implementation constructor locks the implementation instance.
/// @dev Usual deploy path is {PrivacyPortalFactory.createPortal} (clone + initialize in one tx).
///      Split deploy-then-initialize is unsafe: an attacker can front-run `initialize` on an uninitialized clone.
contract PodErc20MintableInitializable is PodErc20Mintable, Initializable {
    /// @notice Lock the implementation instance with placeholder values.
    constructor() PodErc20Mintable(address(1), 1, address(1), address(1), "IMPLEMENTATION", "IMPL") {
        _disableInitializers();
    }

    /// @notice Initialize a mintable source-chain pToken clone.
    /// @param _minter Address allowed to mint (the paired {PrivacyPortal}).
    /// @param _owner Ownable admin allowed to {configure} inbox / COTI peer; factory passes `address(this)`.
    /// @param _cotiChainId COTI chain id for remote MPC execution.
    /// @param _inbox Source-chain inbox.
    /// @param _cotiSideContract COTI-side pToken ledger.
    /// @param _name Token name.
    /// @param _symbol Token symbol.
    /// @param _decimals Token decimals.
    function initialize(
        address _minter,
        address _owner,
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) external initializer {
        if (_owner == address(0)) {
            revert PodERC20InvalidInitialization();
        }
        _initializePodErc20Mintable(_minter, _cotiChainId, _inbox, _cotiSideContract, _name, _symbol, _decimals);
        _transferOwnership(_owner);
    }
}
