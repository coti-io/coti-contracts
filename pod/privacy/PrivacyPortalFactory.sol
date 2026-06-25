// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

import "../IInbox.sol";
import "../token/perc20/PodErc20MintableInitializable.sol";
import "../token/perc20/cotiside/PodErc20CotiMother.sol";
import "./IPrivacyPortal.sol";

/// @title PrivacyPortalFactory
/// @notice Deploys one-shot minimal-clone portals and pTokens for public ERC20 collateral.
contract PrivacyPortalFactory is Ownable {
    /// @notice Source-chain inbox used by pToken clones and registration messages.
    address public immutable inbox;
    /// @notice COTI chain id used by pToken clones for remote MPC execution.
    uint256 public immutable cotiChainId;
    /// @notice Unified COTI-side pToken ledger all clones talk to.
    address public immutable cotiMotherContract;
    /// @notice Clone implementation for source-chain pTokens.
    address public immutable podTokenImplementation;
    /// @notice Clone implementation for portals.
    address public immutable portalImplementation;
    /// @notice Global flag exposed through the pause-controller interface for all portals created here.
    bool public withdrawalsPaused;
    /// @notice Global flag exposed through the pause-controller interface for deposits on factory-created portals.
    bool public depositsPaused;

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
    /// @notice Global deposit pause flag changed.
    event DepositsPausedUpdated(bool paused);
    /// @notice Both deposit and withdrawal pause flags changed together (emergency circuit breaker).
    event OperationsPausedUpdated(bool paused);
    /// @notice A new portal and source-chain pToken clone pair was deployed.
    event PortalCreated(
        address indexed underlying,
        address indexed portal,
        address indexed pToken,
        address cotiMotherContract,
        uint8 decimals
    );
    /// @notice One-way registration message submitted to the COTI mother contract.
    event TokenRegistrationRequested(address indexed pToken, bytes32 indexed requestId);

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
    /// @param cotiMotherContract_ Unified COTI-side pToken ledger.
    /// @param podTokenImplementation_ Clone implementation for source-chain pTokens.
    /// @param portalImplementation_ Clone implementation for portals.
    constructor(
        address initialOwner,
        address inbox_,
        uint256 cotiChainId_,
        address cotiMotherContract_,
        address podTokenImplementation_,
        address portalImplementation_
    ) Ownable(initialOwner) {
        if (
            initialOwner == address(0) || inbox_ == address(0) || cotiChainId_ == 0
                || cotiMotherContract_ == address(0) || podTokenImplementation_ == address(0)
                || portalImplementation_ == address(0)
        ) {
            revert InvalidAddress();
        }
        inbox = inbox_;
        cotiChainId = cotiChainId_;
        cotiMotherContract = cotiMotherContract_;
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

    /// @notice Set the global deposit pause flag read by portals initialized from this factory.
    /// @param paused True to make new deposits / wraps revert.
    function setDepositsPaused(bool paused) external onlyOwner {
        depositsPaused = paused;
        emit DepositsPausedUpdated(paused);
    }

    /// @notice Pause or unpause both deposits and withdrawals (emergency circuit breaker).
    /// @param paused True to halt new deposits and withdrawal requests on factory-created portals.
    function setOperationsPaused(bool paused) external onlyOwner {
        withdrawalsPaused = paused;
        depositsPaused = paused;
        emit OperationsPausedUpdated(paused);
        emit WithdrawalsPausedUpdated(paused);
        emit DepositsPausedUpdated(paused);
    }

    /// @notice Deploy a portal and pToken clone for an underlying token and register on the COTI mother ledger.
    /// @param underlying Public ERC20 collateral token.
    /// @param name Source pToken name.
    /// @param symbol Source pToken symbol.
    /// @param decimals Token decimals.
    /// @param nativeWrappedUnderlying True when underlying is WETH/WAVAX (native wrap deposit + unwrap withdraw).
    /// @param portalOwner Owner assigned to the portal clone.
    /// @return portal Deployed portal clone.
    /// @return pToken Deployed source-chain pToken clone.
    function createPortal(
        address underlying,
        string calldata name,
        string calldata symbol,
        uint8 decimals,
        bool nativeWrappedUnderlying,
        address portalOwner
    ) external payable onlyDeployer returns (address portal, address pToken) {
        if (underlying == address(0) || portalOwner == address(0)) {
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
            cotiMotherContract,
            name,
            symbol,
            decimals
        );
        IPrivacyPortal(portal).initialize(portalOwner, underlying, pToken, decimals, nativeWrappedUnderlying);

        portalForUnderlying[underlying] = portal;
        pTokenForUnderlying[underlying] = pToken;
        portalForPToken[pToken] = portal;

        bytes32 requestId = _requestMotherRegistration(pToken, name, symbol, decimals);

        emit PortalCreated(underlying, portal, pToken, cotiMotherContract, decimals);
        emit TokenRegistrationRequested(pToken, requestId);
    }

    /// @dev Submits a one-way inbox message to register `pToken` on the COTI mother contract.
    function _requestMotherRegistration(
        address pToken,
        string calldata name,
        string calldata symbol,
        uint8 decimals
    ) private returns (bytes32 requestId) {
        IInbox.MpcMethodCall memory methodCall = IInbox.MpcMethodCall({
            selector: bytes4(0),
            data: abi.encodeWithSelector(PodErc20CotiMother.registerToken.selector, pToken, name, symbol, decimals),
            datatypes: new bytes8[](0),
            datalens: new bytes32[](0)
        });

        requestId = IInbox(inbox).sendOneWayMessage{value: msg.value}(
            cotiChainId, cotiMotherContract, methodCall, bytes4(0)
        );
    }
}
