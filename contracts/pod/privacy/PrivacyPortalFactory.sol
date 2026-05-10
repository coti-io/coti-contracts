// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

import "../token/perc20/PodErc20MintableInitializable.sol";
import "./IPrivacyPortal.sol";

/// @title PrivacyPortalFactory
/// @notice Deploys one-shot minimal-clone portals and pTokens for public ERC20 collateral.
contract PrivacyPortalFactory is Ownable {
    /// @notice Source-chain inbox used by pToken clones.
    address public immutable inbox;
    /// @notice COTI chain id used by pToken clones for remote MPC execution.
    uint256 public immutable cotiChainId;
    /// @notice Clone implementation for source-chain pTokens.
    address public immutable podTokenImplementation;
    /// @notice Clone implementation for portals.
    address public immutable portalImplementation;
    /// @notice Global flag exposed through the pause-controller interface for all portals created here.
    bool public withdrawalsPaused;

    /// @notice Addresses allowed to deploy portal/pToken pairs.
    mapping(address => bool) public deployers;
    /// @notice Portal address by underlying ERC20.
    mapping(address => address) public portalForUnderlying;
    /// @notice Source-chain pToken address by underlying ERC20.
    mapping(address => address) public pTokenForUnderlying;
    /// @notice Portal address by source-chain pToken.
    mapping(address => address) public portalForPToken;

    /// @notice Deployer allowlist entry changed.
    event DeployerUpdated(address indexed deployer, bool allowed);
    /// @notice Global withdrawal pause flag changed.
    event WithdrawalsPausedUpdated(bool paused);
    /// @notice A new portal and source-chain pToken clone pair was deployed.
    event PortalCreated(
        address indexed underlying,
        address indexed portal,
        address indexed pToken,
        address cotiSideToken,
        uint8 decimals
    );

    /// @notice Caller is not an allowlisted deployer.
    error OnlyDeployer(address caller);
    /// @notice A required address was zero.
    error InvalidAddress();
    /// @notice A portal already exists for the underlying token.
    error PortalAlreadyExists(address underlying, address portal);

    /// @notice Restrict a function to an allowlisted deployer.
    modifier onlyDeployer() {
        if (!deployers[msg.sender]) {
            revert OnlyDeployer(msg.sender);
        }
        _;
    }

    /// @param initialOwner Owner and initial deployer.
    /// @param inbox_ Source-chain inbox used by pToken clones.
    /// @param cotiChainId_ COTI chain id used by pToken clones.
    /// @param podTokenImplementation_ Clone implementation for source-chain pTokens.
    /// @param portalImplementation_ Clone implementation for portals.
    constructor(
        address initialOwner,
        address inbox_,
        uint256 cotiChainId_,
        address podTokenImplementation_,
        address portalImplementation_
    ) Ownable(initialOwner) {
        if (
            initialOwner == address(0) || inbox_ == address(0) || cotiChainId_ == 0
                || podTokenImplementation_ == address(0) || portalImplementation_ == address(0)
        ) {
            revert InvalidAddress();
        }
        inbox = inbox_;
        cotiChainId = cotiChainId_;
        podTokenImplementation = podTokenImplementation_;
        portalImplementation = portalImplementation_;
        deployers[initialOwner] = true;
        emit DeployerUpdated(initialOwner, true);
    }

    /// @notice Add or remove a portal deployer.
    /// @param deployer Address to update.
    /// @param allowed Whether the address may create portals.
    function setDeployer(address deployer, bool allowed) external onlyOwner {
        if (deployer == address(0)) {
            revert InvalidAddress();
        }
        deployers[deployer] = allowed;
        emit DeployerUpdated(deployer, allowed);
    }

    /// @notice Set the global pause flag read by portals initialized from this factory.
    /// @param paused True to make new withdrawal requests revert.
    function setWithdrawalsPaused(bool paused) external onlyOwner {
        withdrawalsPaused = paused;
        emit WithdrawalsPausedUpdated(paused);
    }

    /// @notice Deploy a portal and pToken clone for an underlying token.
    /// @param underlying Public ERC20 collateral token.
    /// @param cotiSideToken COTI-side pToken ledger paired to the source pToken.
    /// @param name Source pToken name.
    /// @param symbol Source pToken symbol.
    /// @param decimals Token decimals.
    /// @param portalOwner Owner assigned to the portal clone.
    /// @return portal Deployed portal clone.
    /// @return pToken Deployed source-chain pToken clone.
    function createPortal(
        address underlying,
        address cotiSideToken,
        string calldata name,
        string calldata symbol,
        uint8 decimals,
        address portalOwner
    ) external onlyDeployer returns (address portal, address pToken) {
        if (underlying == address(0) || cotiSideToken == address(0) || portalOwner == address(0)) {
            revert InvalidAddress();
        }
        if (portalForUnderlying[underlying] != address(0)) {
            revert PortalAlreadyExists(underlying, portalForUnderlying[underlying]);
        }

        portal = Clones.clone(portalImplementation);
        pToken = Clones.clone(podTokenImplementation);

        PodErc20MintableInitializable(payable(pToken)).initialize(
            portal,
            cotiChainId,
            inbox,
            cotiSideToken,
            name,
            symbol,
            decimals
        );
        IPrivacyPortal(portal).initialize(portalOwner, underlying, pToken, decimals);

        portalForUnderlying[underlying] = portal;
        pTokenForUnderlying[underlying] = pToken;
        portalForPToken[pToken] = portal;

        emit PortalCreated(underlying, portal, pToken, cotiSideToken, decimals);
    }
}
