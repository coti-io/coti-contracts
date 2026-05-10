// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./PodERC20.sol";

/// @title PodErc20Mintable
/// @notice {PodERC20} variant that permits `mint` calls from a single immutable `minter` address.
/// @dev The minter is set at construction and cannot change. To rotate minters, deploy a new token or subclass with
///      a mutable `minter` plus access control. All other behavior (transfers, approvals, burns, syncing) is inherited
///      verbatim from {PodERC20}.
contract PodErc20Mintable is PodERC20 {
    /// @notice Sole address allowed to call {PodERC20.mint} (encrypted or plain variant).
    address public minter;
    bool private _mintableInitialized;

    /// @notice Thrown when a non-minter tries to mint; carries the caller for debugging.
    error OnlyMinter(address caller);
    /// @notice Mintable storage was already initialized.
    error PodErc20MintableAlreadyInitialized();
    /// @notice Minter was the zero address.
    error PodErc20MintableInvalidMinter();

    /**
     * @param _minter Address authorized to mint; must not be zero.
     * @param _cotiChainId See {PodERC20}.
     * @param _inbox See {PodERC20}.
     * @param _cotiSideContract See {PodERC20}.
     * @param _name See {PodERC20}.
     * @param _symbol See {PodERC20}.
     */
    constructor(
        address _minter,
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol
    ) PodERC20(_cotiChainId, _inbox, _cotiSideContract, _name, _symbol) {
        _initializeMintableMinter(_minter);
    }

    /// @inheritdoc PodERC20
    /// @dev Allows the call only when `msg.sender == minter`; reverts with {OnlyMinter} otherwise.
    function _checkMinter() internal view override {
        if (msg.sender != minter) {
            revert OnlyMinter(msg.sender);
        }
    }

    /// @notice Initialize mintable token storage with default 18 decimals.
    function _initializePodErc20Mintable(
        address _minter,
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol
    ) internal {
        _initializePodErc20Mintable(_minter, _cotiChainId, _inbox, _cotiSideContract, _name, _symbol, 18);
    }

    /// @notice Initialize mintable token storage with explicit decimals.
    function _initializePodErc20Mintable(
        address _minter,
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) internal {
        _initializePodERC20(_cotiChainId, _inbox, _cotiSideContract, _name, _symbol, _decimals);
        _initializeMintableMinter(_minter);
    }

    /// @notice Initialize the immutable-style minter slot for constructors and clones.
    /// @param _minter Address authorized to mint; must not be zero.
    function _initializeMintableMinter(address _minter) internal {
        if (_mintableInitialized) {
            revert PodErc20MintableAlreadyInitialized();
        }
        if (_minter == address(0)) {
            revert PodErc20MintableInvalidMinter();
        }
        _mintableInitialized = true;
        minter = _minter;
    }
}
