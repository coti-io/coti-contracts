// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../../../utils/mpc/MpcCore.sol";
import "./Erc7984Constants.sol";
import "./Erc7984Pointers.sol";
import "./IERC7984.sol";

/// @title PodErc7984Mixin
/// @notice ERC-7984 explorer compatibility for PoD pTokens. Emits `ConfidentialTransfer` on async callback success.
/// @dev Mixed into {PodERC20}. Use native {IPodERC20} async methods for transfers; ERC-7984 transfer entry points revert.
abstract contract PodErc7984Mixin is IERC7984, ERC165 {
    /// @notice ERC-7572 metadata URI for explorers (optional).
    string public contractURI;

    /// @dev Last confidential amount handle emitted on callback; portals may read for unwrap finalization events.
    bytes32 public lastConfidentialTransferHandle;

    /// @dev ERC-7984 operator approvals (separate from async pToken allowance model).
    mapping(address => mapping(address => uint48)) private _operatorUntil;

    /// @notice Thrown when an ERC-7984 transfer method is invoked; use {IPodERC20} async entry points instead.
    error Erc7984UsePodTransferMethods();

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165, IERC165)
        returns (bool)
    {
        return interfaceId == Erc7984Constants.INTERFACE_ID || interfaceId == type(IERC7984).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IERC7984
    function confidentialTotalSupply() external pure returns (bytes32) {
        return bytes32(0);
    }

    /// @inheritdoc IERC7984
    function confidentialBalanceOf(address account) external view returns (bytes32) {
        return Erc7984Pointers.toHandle(_erc7984BalanceOf(account));
    }

    /// @inheritdoc IERC7984
    function isOperator(address holder, address spender) public view returns (bool) {
        return _operatorUntil[holder][spender] > block.timestamp;
    }

    /// @inheritdoc IERC7984
    function setOperator(address operator, uint48 until) external {
        _operatorUntil[msg.sender][operator] = until;
        emit OperatorSet(msg.sender, operator, until);
    }

    /// @inheritdoc IERC7984
    function confidentialTransfer(address, bytes32) external payable returns (bytes32) {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransfer(address, bytes32, bytes calldata) external payable returns (bytes32) {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransferFrom(address, address, bytes32) external payable returns (bytes32) {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransferFrom(address, address, bytes32, bytes calldata) external payable returns (bytes32) {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransferAndCall(address, bytes32, bytes calldata) external payable returns (bytes32) {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransferAndCall(address, bytes32, bytes calldata, bytes calldata)
        external
        payable
        returns (bytes32)
    {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransferFromAndCall(address, address, bytes32, bytes calldata)
        external
        payable
        returns (bytes32)
    {
        revert Erc7984UsePodTransferMethods();
    }

    /// @inheritdoc IERC7984
    function confidentialTransferFromAndCall(address, address, bytes32, bytes calldata, bytes calldata)
        external
        payable
        returns (bytes32)
    {
        revert Erc7984UsePodTransferMethods();
    }

    /// @dev Emit ERC-7984 transfer row for explorers after COTI callback applied balances.
    function _emitConfidentialTransfer(
        address from,
        address to,
        ctUint256 memory senderValue,
        ctUint256 memory receiverValue
    ) internal {
        bytes32 handle = Erc7984Pointers.transferAmountHandle(from, to, senderValue, receiverValue);
        lastConfidentialTransferHandle = handle;
        emit ConfidentialTransfer(from, to, handle);
    }

    /// @dev Child returns cached PoD balance ciphertext for `account`.
    function _erc7984BalanceOf(address account) internal view virtual returns (ctUint256 memory);
}
