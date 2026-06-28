// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IInboxFeeManager
/// @notice Read-only fee estimation surface exposed by inbox contracts for PoD dapps.
interface IInboxFeeManager {
    /// @notice Template for minimum fees in gas units.
    struct FeeConfig {
        uint256 constantFee;
        uint256 gasPerByte;
        uint256 callbackExecutionGas;
        uint256 errorLength;
        uint256 bufferRatioX10000;
    }

    /// @notice Oracle used to convert gas budgets between local and remote fee tokens.
    function priceOracle() external view returns (address);

    /// @notice Minimum fee template for the local callback leg.
    function localMinFeeConfig() external view returns (FeeConfig memory);

    /// @notice Minimum fee template for the remote execution leg.
    function remoteMinFeeConfig() external view returns (FeeConfig memory);

    /// @notice Estimate the local-token wei required for a two-way message.
    /// @param remoteMethodCallSize Remote calldata size term.
    /// @param callBackMethodCallSize Callback calldata size term.
    /// @param remoteMethodExecutionGas Remote execution gas term.
    /// @param callBackMethodExecutionGas Callback execution gas term.
    /// @param gasPrice Wei per gas assumption.
    /// @return targetFeeLocalWei Local-token wei estimated for the remote execution leg.
    /// @return callerFeeLocalWei Local-token wei estimated for the callback leg.
    function calculateTwoWayFeeRequiredInLocalToken(
        uint256 remoteMethodCallSize,
        uint256 callBackMethodCallSize,
        uint256 remoteMethodExecutionGas,
        uint256 callBackMethodExecutionGas,
        uint256 gasPrice
    ) external view returns (uint256 targetFeeLocalWei, uint256 callerFeeLocalWei);
}
