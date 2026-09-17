// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./IPodPriceOracle.sol";

/// @title PortalFeeOracle
/// @notice Testnet/manual oracle: all live reads return admin-set pegs (no external feeds).
/// @dev Trust model: `owner` fully controls rates. Zero prices disable dynamic portal fees (fixed fee only).
///      Admins validate any live oracle off-chain before wiring the factory — no on-chain interface gate.
contract PortalFeeOracle is IPodPriceOracle, Ownable {
    /// @notice USD peg per token (18 decimals per whole token).
    mapping(address => uint256) public tokenPriceUSD;

    /// @notice Timestamp of the last genuine {setTokenPriceUSD} write per token.
    mapping(address => uint64) public tokenPriceUpdatedAt;

    /// @notice USD peg must be non-zero.
    error ZeroUsdPrice();

    /// @notice Token address was zero.
    error ZeroToken();
    /// @notice Ownership cannot be renounced (admin must remain reachable).
    error OwnershipCannotBeRenounced();

    event TokenPriceUpdated(address indexed token, uint256 priceUsd);

    /// @param initialOwner Admin allowed to set rates.
    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Ownership cannot be renounced (price admin must remain reachable).
    function renounceOwnership() public pure override {
        revert OwnershipCannotBeRenounced();
    }

    /// @notice Set USD peg for `token`.
    /// @param priceUsd 18-decimal USD per whole token (must be non-zero).
    function setTokenPriceUSD(address token, uint256 priceUsd) external onlyOwner {
        if (token == address(0)) {
            revert ZeroToken();
        }
        if (priceUsd == 0) {
            revert ZeroUsdPrice();
        }
        tokenPriceUSD[token] = priceUsd;
        tokenPriceUpdatedAt[token] = uint64(block.timestamp);
        emit TokenPriceUpdated(token, priceUsd);
    }

    /// @notice Clear the USD peg for `token` (dynamic fees fall back to fixed fee for that leg).
    function clearTokenPriceUSD(address token) external onlyOwner {
        if (token == address(0)) {
            revert ZeroToken();
        }
        delete tokenPriceUSD[token];
        delete tokenPriceUpdatedAt[token];
        emit TokenPriceUpdated(token, 0);
    }

    /// @notice Price plus last-write timestamp for ops / health bots.
    /// @dev On-chain fee math uses {getLivePrices} / {getLivePrice} only — timestamps are not a fail-closed gate.
    function getTokenPriceMeta(address token) external view returns (uint256 priceUsd, uint64 updatedAt) {
        return (tokenPriceUSD[token], tokenPriceUpdatedAt[token]);
    }

    /// @inheritdoc IPodPriceOracle
    function getLivePrice(address token) external view returns (uint256 priceUsd) {
        return tokenPriceUSD[token];
    }

    /// @inheritdoc IPodPriceOracle
    function getLivePrices(address nativeToken, address collateralToken)
        external
        view
        returns (uint256 nativeUsd, uint256 collateralUsd)
    {
        return (tokenPriceUSD[nativeToken], tokenPriceUSD[collateralToken]);
    }
}
