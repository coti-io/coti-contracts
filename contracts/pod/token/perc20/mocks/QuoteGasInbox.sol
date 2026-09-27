// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../../IInbox.sol";

interface IQuoteTarget {
    function estimateFee() external view returns (uint256 totalFeeWei, uint256 targetFeeWei, uint256 callbackFeeWei);
}

/// @dev Inbox stand-in for the PodERC20 quote-vs-send gas price test.
///      Quote multiplies a fixed gas-unit count by the price the caller passes.
///      Send accepts only if that slice covers the same count at {FeeManager._referenceGasPrice}.
contract QuoteGasInbox {
    uint256 public constant GAS_UNITS = 1000;
    uint256 public minPriorityFeeWei;
    uint256 public minGasPriceWei;
    uint256 public maxGasPriceWei;

    uint256 public lastCallbackFee;
    uint256 public lastReferenceGasPrice;

    constructor(uint256 minPriorityFeeWei_, uint256 minGasPriceWei_, uint256 maxGasPriceWei_) {
        minPriorityFeeWei = minPriorityFeeWei_;
        minGasPriceWei = minGasPriceWei_;
        maxGasPriceWei = maxGasPriceWei_;
    }

    function DEFAULT_GAS_PRICE() public pure returns (uint256) {
        return 2_000_000_000;
    }

    /// @dev Same formula as {FeeManager._referenceGasPrice}. `minGasPriceWei` is stored non-zero in tests.
    function referenceGasPrice() public view returns (uint256 gasPrice) {
        if (block.basefee > 0) {
            gasPrice = block.basefee + minPriorityFeeWei;
        } else {
            uint256 txPrice = tx.gasprice;
            gasPrice = txPrice != 0 ? txPrice : DEFAULT_GAS_PRICE();
        }
        if (gasPrice < minGasPriceWei) gasPrice = minGasPriceWei;
        if (maxGasPriceWei != 0 && gasPrice > maxGasPriceWei) gasPrice = maxGasPriceWei;
    }

    function calculateTwoWayFeeRequiredInLocalToken(uint256, uint256, uint256, uint256, uint256 gasPrice)
        external
        pure
        returns (uint256 targetFeeLocalWei, uint256 callerFeeLocalWei)
    {
        targetFeeLocalWei = GAS_UNITS * gasPrice;
        callerFeeLocalWei = GAS_UNITS * gasPrice;
    }

    /// @dev Runs in a real transaction so `basefee` is the block base fee. `eth_call` on this
    ///      network reports `basefee == 0`, which is a different path.
    function recordQuote(address pToken) external {
        (, uint256 targetFee, uint256 callbackFee) = IQuoteTarget(pToken).estimateFee();
        uint256 ref = referenceGasPrice();
        require(targetFee == GAS_UNITS * ref && callbackFee == GAS_UNITS * ref, "quote != reference");
        lastCallbackFee = callbackFee;
        lastReferenceGasPrice = ref;
    }

    function sendTwoWayMessage(
        uint256,
        address,
        IInbox.MpcMethodCall calldata,
        bytes4,
        bytes4,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32) {
        uint256 ref = referenceGasPrice();
        uint256 minSlice = GAS_UNITS * ref;
        require(callbackFeeLocalWei >= minSlice, "callback short");
        require(msg.value >= callbackFeeLocalWei + minSlice, "target short");
        lastCallbackFee = callbackFeeLocalWei;
        lastReferenceGasPrice = ref;
        return bytes32(uint256(1));
    }
}
