// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./IPodPriceOracle.sol";

/// @title PortalFeeOracle
/// @notice Testnet/manual oracle: all live reads return admin-set pegs (no external feeds).
/// @dev Trust model: `owner` fully controls rates. Zero prices disable dynamic portal fees (fixed fee only).
contract PortalFeeOracle is IPodPriceOracle, Ownable {
    /// @notice USD peg per token (18 decimals per whole token).
    mapping(address => uint256) public tokenPriceUSD;

    /// @notice USD peg must be non-zero.
    error ZeroUsdPrice();

    /// @notice Token address was zero.
    error ZeroToken();

    event TokenPriceUpdated(address indexed token, uint256 priceUsd);

    /// @param initialOwner Admin allowed to set rates.
    constructor(address initialOwner) Ownable(initialOwner) {}

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
        emit TokenPriceUpdated(token, priceUsd);
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
