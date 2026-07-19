// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";

import "../IPodPriceOracle.sol";
import "../IPrivacyPortalFactory.sol";
import "../PrivacyPortalFeeLib.sol";

/// @dev Minimal factory for direct PrivacyPortal unit tests (zero portal fees by default).
contract MockPrivacyPortalFactory is IPrivacyPortalFactory, Pausable {
    address public immutable feeRecipient;
    address public rescueRecipient;
    address public immutable nativeToken;
    address public immutable owner_;
    IPodPriceOracle public priceOracle;
    bytes32 public defaultDepositFeePacked;
    bytes32 public defaultWithdrawFeePacked;
    mapping(address => bool) public blacklisted;
    mapping(address => bool) public operators;

    constructor(address feeRecipient_, address nativeToken_) {
        feeRecipient = feeRecipient_;
        rescueRecipient = feeRecipient_;
        nativeToken = nativeToken_;
        owner_ = feeRecipient_;
        operators[feeRecipient_] = true;
        defaultDepositFeePacked = PrivacyPortalFeeLib.packFeeConfig(0, 0, type(uint128).max);
        defaultWithdrawFeePacked = PrivacyPortalFeeLib.packFeeConfig(0, 0, type(uint128).max);
    }

    function setRescueRecipient(address rescueRecipient_) external {
        rescueRecipient = rescueRecipient_;
    }

    function owner() external view returns (address) {
        return owner_;
    }

    function isAdmin(address account) external view returns (bool) {
        return account == owner_;
    }

    function isOperator(address account) external view returns (bool) {
        return operators[account];
    }

    function setOperator(address account, bool allowed) external {
        operators[account] = allowed;
    }

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }

    function depositsPaused() external view returns (bool) {
        return paused();
    }

    function withdrawalsPaused() external view returns (bool) {
        return paused();
    }

    function setBlacklisted(address account, bool blocked) external {
        blacklisted[account] = blocked;
    }

    function setDefaultDepositFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external {
        defaultDepositFeePacked = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
    }

    function setDefaultWithdrawFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external {
        defaultWithdrawFeePacked = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
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
