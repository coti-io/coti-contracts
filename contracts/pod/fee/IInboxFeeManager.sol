// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IInboxFeeManager
/// @notice Read-only fee estimation surface exposed by inbox contracts for PoD dapps.
interface IInboxFeeManager {
    /// @notice Template for minimum fees in gas units plus hard admission caps.
    /// @dev Packed as seven `uint32`s + two `uint16`s (one storage slot). Values fit well below
    ///      type maxima. `maxMethodCallBytes` / `maxExecutionGas` are always required (including when
    ///      `constantFee > 0`). `gasPriceMul` / `gasPriceDiv` skew wei→gas (default 1/1; both non-zero).
    ///      Size caps use **payload weight** = `data.length + datatypes.length*32 + datalens.length*32`
    ///      (not `abi.encode(methodCall).length`).
    struct FeeConfig {
        uint32 constantFee;
        uint32 gasPerByte;
        uint32 callbackExecutionGas;
        uint32 errorLength;
        uint32 bufferRatioX10000;
        /// @notice Max method-call payload weight (bytes) for create/ingest admission.
        uint32 maxMethodCallBytes;
        /// @notice Max gas-unit budget allowed on `targetFee` / `callerFee` fields.
        uint32 maxExecutionGas;
        /// @notice Numerator for gas-price skew vs peer chain. Default 1.
        uint16 gasPriceMul;
        /// @notice Denominator for gas-price skew vs peer chain. Default 1; must be non-zero.
        uint16 gasPriceDiv;
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
