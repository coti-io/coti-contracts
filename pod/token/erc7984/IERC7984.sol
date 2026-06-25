// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IERC7984
/// @notice Draft ERC-7984 confidential fungible token interface (pointer-based amounts).
/// @dev Technology-agnostic EIP-7984 surface for Blockscout and other indexers. PoD pTokens
///      implement this for explorer compatibility; execution remains async via inbox + COTI.
interface IERC7984 is IERC165 {
    /// @dev Emitted when a confidential transfer completes (including mint/burn via zero address).
    event ConfidentialTransfer(address indexed from, address indexed to, bytes32 indexed amount);

    /// @dev Emitted when an operator authorization is updated.
    event OperatorSet(address indexed holder, address indexed operator, uint48 until);

    /// @dev Optional: emitted when a pointer amount is publicly disclosed.
    event AmountDisclosed(bytes32 indexed handle, uint256 amount);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    function contractURI() external view returns (string memory);

    function confidentialTotalSupply() external view returns (bytes32);

    function confidentialBalanceOf(address account) external view returns (bytes32);

    function isOperator(address holder, address spender) external view returns (bool);

    function setOperator(address operator, uint48 until) external;

    function confidentialTransfer(address to, bytes32 amount) external payable returns (bytes32);

    function confidentialTransfer(address to, bytes32 amount, bytes calldata data) external payable returns (bytes32);

    function confidentialTransferFrom(address from, address to, bytes32 amount) external payable returns (bytes32);

    function confidentialTransferFrom(address from, address to, bytes32 amount, bytes calldata data)
        external
        payable
        returns (bytes32);

    function confidentialTransferAndCall(address to, bytes32 amount, bytes calldata callData)
        external
        payable
        returns (bytes32);

    function confidentialTransferAndCall(address to, bytes32 amount, bytes calldata data, bytes calldata callData)
        external
        payable
        returns (bytes32);

    function confidentialTransferFromAndCall(address from, address to, bytes32 amount, bytes calldata callData)
        external
        payable
        returns (bytes32);

    function confidentialTransferFromAndCall(
        address from,
        address to,
        bytes32 amount,
        bytes calldata data,
        bytes calldata callData
    ) external payable returns (bytes32);
}
