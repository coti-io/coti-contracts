// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPrivacyPortalFactoryAdmin
/// @notice Admin / operator / deployer surface for {PrivacyPortalFactory}.
/// @dev Portal clones continue to use the narrower {IPrivacyPortalFactory} (fees, pause flags, blacklist, roles).
///      Tooling and ops scripts should depend on this interface for upgrade, remount, and governance actions.
///      Role management (`grantRole` / `revokeRole`) and factory-wide `pause` / `unpause` come from OpenZeppelin
///      {AccessControl} / {Pausable} on the concrete factory — not redeclared here (avoids override clashes).
interface IPrivacyPortalFactoryAdmin {
    // ── Implementation / routing ───────────────────────────────────────────────
    function setPortalImplementation(address portalImplementation_) external;
    function setPodTokenImplementation(address podTokenImplementation_) external;
    function configureRouting(address inbox_, uint256 cotiChainId_, address cotiMotherContract_) external;
    function configurePToken(address pToken_, address inbox_, address cotiSideContract_) external;
    function transferPTokenOwnership(address pToken_, address newOwner_) external;
    function setRescueRecipient(address rescueRecipient_) external;
    function setPriceOracle(address newOracle) external;

    // ── Deployers / blacklist ──────────────────────────────────────────────────
    function setDeployer(address deployer, bool allowed) external;
    function addToBlacklist(address account) external;
    function removeFromBlacklist(address account) external;

    // ── Default fees (operator) ────────────────────────────────────────────────
    function setDefaultDepositFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external;
    function setDefaultWithdrawFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external;

    // ── Portal creation / remount ──────────────────────────────────────────────
    function createPortal(
        address underlying,
        string calldata name,
        string calldata symbol,
        uint8 decimals,
        bool nativeWrappedUnderlying
    ) external payable returns (address portal, address pToken);

    /// @notice Attach or remount an existing factory-owned pToken onto a new portal clone (no mother re-registration).
    /// @dev Remount requires the old portal to be paused. Native-wrapped portals must remount with
    ///      `nativeWrappedUnderlying == true`. New portal is created paused; migrate funds then unpause.
    function createPortalWithExistingPToken(
        address underlying,
        address existingPToken,
        bool nativeWrappedUnderlying
    ) external returns (address portal);
}
