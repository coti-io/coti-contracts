// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IPodPriceOracle.sol";
import "../IPrivacyPortalFactory.sol";
import "../PrivacyPortalFeeLib.sol";

/// @dev Minimal factory for direct PrivacyPortal unit tests (zero portal fees by default).
contract MockPrivacyPortalFactory is IPrivacyPortalFactory {
    address public immutable feeRecipient;
    address public immutable nativeToken;
    bool public withdrawalsPaused;
    bool public depositsPaused;
    IPodPriceOracle public priceOracle;
    bytes32 public defaultDepositFeePacked;
    bytes32 public defaultWithdrawFeePacked;

    constructor(address feeRecipient_, address nativeToken_) {
        feeRecipient = feeRecipient_;
        nativeToken = nativeToken_;
        defaultDepositFeePacked = PrivacyPortalFeeLib.packFeeConfig(0, 0, type(uint128).max);
        defaultWithdrawFeePacked = PrivacyPortalFeeLib.packFeeConfig(0, 0, type(uint128).max);
    }

    function setWithdrawalsPaused(bool paused) external {
        withdrawalsPaused = paused;
    }

    function setDepositsPaused(bool paused) external {
        depositsPaused = paused;
    }

    function estimateDepositPortalFee(address, uint256, uint8)
        external
        view
        returns (uint256 fee, bool usedDynamicPricing)
    {
        (uint96 fixedFee,,) = PrivacyPortalFeeLib.unpackFeeConfig(defaultDepositFeePacked);
        return (fixedFee, false);
    }

    function estimateWithdrawPortalFee(address, uint256, uint8)
        external
        view
        returns (uint256 fee, bool usedDynamicPricing)
    {
        (uint96 fixedFee,,) = PrivacyPortalFeeLib.unpackFeeConfig(defaultWithdrawFeePacked);
        return (fixedFee, false);
    }

    function getDepositPortalFeeFloor(address, uint256, uint8)
        external
        view
        returns (uint256 floor, uint128 maxFee)
    {
        (uint96 fixedFee,, uint128 max) = PrivacyPortalFeeLib.unpackFeeConfig(defaultDepositFeePacked);
        return (fixedFee, max);
    }

    function getWithdrawPortalFeeFloor(address, uint256, uint8)
        external
        view
        returns (uint256 floor, uint128 maxFee)
    {
        (uint96 fixedFee,, uint128 max) = PrivacyPortalFeeLib.unpackFeeConfig(defaultWithdrawFeePacked);
        return (fixedFee, max);
    }

    function getFeeConfig(bool isDeposit) external view returns (PortalFeeConfig memory config) {
        return PrivacyPortalFeeLib.decodeFeeConfig(
            isDeposit ? defaultDepositFeePacked : defaultWithdrawFeePacked
        );
    }

    function decodeFeeConfig(bytes32 packed) external pure returns (PortalFeeConfig memory config) {
        return PrivacyPortalFeeLib.decodeFeeConfig(packed);
    }
}
