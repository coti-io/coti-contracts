// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IERC7984PortalWrapper
/// @notice Partial ERC-7984 wrapper surface for PrivacyPortal deposit/withdraw explorer visibility.
/// @dev Does not require full synchronous wrap/unwrap semantics; events mirror OpenZeppelin/Zama naming.
interface IERC7984PortalWrapper {
    /// @dev Emitted when underlying is locked and a confidential mint is requested (portal deposit / wrap).
    event WrapRequested(address indexed from, address indexed to, uint256 amount, bytes32 indexed mintRequestId);

    /// @dev Emitted when a confidential unwrap is requested (portal withdrawal).
    event UnwrapRequested(address indexed receiver, bytes32 indexed unwrapRequestId, bytes32 amount);

    /// @dev Emitted when underlying is released after a confidential unwrap completes.
    /// @param encryptedAmount PoD portals use `unwrapRequestId` as an explorer correlation id; the
    ///        real confidential amount pointer is on the pToken `ConfidentialTransfer` in the callback tx.
    event UnwrapFinalized(
        address indexed receiver,
        bytes32 indexed unwrapRequestId,
        bytes32 encryptedAmount,
        uint64 cleartextAmount
    );

    function underlying() external view returns (address);

    /// @dev Conversion rate from underlying to confidential token (1:1 for PoD portals).
    function rate() external view returns (uint256);

    /// @notice Lock underlying and request async confidential mint (alias for deposit with explicit fee).
    function wrap(address to, uint256 amount, uint256 mintCallbackFee) external payable returns (bytes32);
}
