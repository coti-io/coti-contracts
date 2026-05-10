// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

import "../token/perc20/cotiside/PodErc20CotiSideInitializable.sol";

/// @title PodErc20CotiSideFactory
/// @notice Deploys clone-based COTI-side pToken ledgers for the PoD privacy portal.
contract PodErc20CotiSideFactory is Ownable {
    /// @notice COTI-side inbox used by deployed token clones.
    address public immutable inbox;
    /// @notice Current clone implementation for COTI-side pToken ledgers.
    address public implementation;

    /// @notice Addresses allowed to deploy COTI-side token clones.
    mapping(address => bool) public deployers;
    /// @notice Append-only deployment registry. Prefer {CotiSideTokenCreated} for indexing; use paginated reads on-chain.
    address[] public allCotiSideTokens;

    /// @notice Deployer allowlist entry changed.
    event DeployerUpdated(address indexed deployer, bool allowed);
    /// @notice Clone implementation address changed.
    event ImplementationUpdated(address indexed implementation);
    /// @notice A COTI-side pToken clone was deployed.
    event CotiSideTokenCreated(address indexed cotiSideToken, address indexed owner);

    /// @notice Caller is not an allowlisted deployer.
    error OnlyDeployer(address caller);
    /// @notice A required address was zero.
    error InvalidAddress();

    /// @notice Restrict a function to an allowlisted deployer.
    modifier onlyDeployer() {
        if (!deployers[msg.sender]) {
            revert OnlyDeployer(msg.sender);
        }
        _;
    }

    /// @param initialOwner Owner and initial deployer.
    /// @param inbox_ COTI-side inbox assigned to clones.
    /// @param implementation_ Initial clone implementation.
    constructor(address initialOwner, address inbox_, address implementation_) Ownable(initialOwner) {
        if (initialOwner == address(0) || inbox_ == address(0) || implementation_ == address(0)) {
            revert InvalidAddress();
        }
        inbox = inbox_;
        implementation = implementation_;
        deployers[initialOwner] = true;
        emit DeployerUpdated(initialOwner, true);
        emit ImplementationUpdated(implementation_);
    }

    /// @notice Add or remove a COTI-side token deployer.
    /// @param deployer Address to update.
    /// @param allowed Whether the address may create token clones.
    function setDeployer(address deployer, bool allowed) external onlyOwner {
        if (deployer == address(0)) {
            revert InvalidAddress();
        }
        deployers[deployer] = allowed;
        emit DeployerUpdated(deployer, allowed);
    }

    /// @notice Replace the implementation used for future clones.
    /// @param implementation_ New implementation address.
    function setImplementation(address implementation_) external onlyOwner {
        if (implementation_ == address(0)) {
            revert InvalidAddress();
        }
        implementation = implementation_;
        emit ImplementationUpdated(implementation_);
    }

    /// @notice Deploy a COTI-side pToken ledger clone.
    /// @param tokenOwner Owner assigned to the clone.
    /// @return cotiSideToken Deployed clone address.
    function createCotiSideToken(address tokenOwner) external onlyDeployer returns (address cotiSideToken) {
        if (tokenOwner == address(0)) {
            revert InvalidAddress();
        }
        cotiSideToken = Clones.clone(implementation);
        PodErc20CotiSideInitializable(cotiSideToken).initialize(inbox, tokenOwner);
        allCotiSideTokens.push(cotiSideToken);
        emit CotiSideTokenCreated(cotiSideToken, tokenOwner);
    }

    /// @notice Number of COTI-side token clones deployed through this factory.
    function allCotiSideTokensLength() external view returns (uint256) {
        return allCotiSideTokens.length;
    }

    /// @notice Paginated view over deployed COTI-side token clones.
    /// @param offset First array index to return.
    /// @param limit Maximum number of addresses to return.
    /// @return tokens Slice of deployed token addresses.
    function getCotiSideTokens(uint256 offset, uint256 limit) external view returns (address[] memory tokens) {
        uint256 total = allCotiSideTokens.length;
        if (offset >= total || limit == 0) {
            return new address[](0);
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        tokens = new address[](end - offset);
        for (uint256 i = 0; i < tokens.length; ++i) {
            tokens[i] = allCotiSideTokens[offset + i];
        }
    }
}
