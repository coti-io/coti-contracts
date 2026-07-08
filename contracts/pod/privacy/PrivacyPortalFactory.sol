// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

import "../IInbox.sol";
import "../token/perc20/PodErc20MintableInitializable.sol";
import "../token/perc20/cotiside/PodErc20CotiMother.sol";
import "./IPrivacyPortal.sol";
import "./IPrivacyPortalFactory.sol";
import "./IPodPriceOracle.sol";
import "./PrivacyPortalFeeLib.sol";

/// @title PrivacyPortalFactory
/// @notice Deploys one-shot minimal-clone portals and pTokens for public ERC20 collateral.
contract PrivacyPortalFactory is IPrivacyPortalFactory, Ownable {
    using PrivacyPortalFeeLib for bytes32;

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
    /// @notice Recipient of swept portal protocol fees from all portals created here.
    address public immutable feeRecipient;
    /// @notice Wrapped native token on this chain (WETH/WAVAX) for portal gas fee pricing.
    address public immutable nativeToken;
    /// @notice Global flag exposed through the pause-controller interface for all portals created here.
    bool public withdrawalsPaused;
    /// @notice Global flag exposed through the pause-controller interface for deposits on factory-created portals.
    bool public depositsPaused;

    /// @notice Optional USD oracle for dynamic portal fees; zero disables dynamic pricing.
    IPodPriceOracle public priceOracle;
    /// @notice Factory default packed deposit fee config.
    bytes32 public defaultDepositFeePacked;
    /// @notice Factory default packed withdraw fee config.
    bytes32 public defaultWithdrawFeePacked;

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
    /// @notice Factory default portal fee config updated.
    event DefaultPortalFeeUpdated(bool indexed isDeposit, bytes32 packedConfig);
    /// @notice Portal fee oracle upgraded or disabled.
    event PriceOracleUpdated(address indexed previousOracle, address indexed newOracle);

    /// @notice Caller is not an allowlisted deployer.
    error OnlyDeployer(address caller);
    /// @notice A required address was zero.
    error InvalidAddress();
    /// @notice A portal already exists for the underlying token.
    error PortalAlreadyExists(address underlying, address portal);
    /// @notice Oracle is not configured.
    error OracleNotConfigured();

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
    /// @param feeRecipient_ Recipient of swept portal protocol fees.
    /// @param nativeToken_ Wrapped native token (WETH/WAVAX) for dynamic fee gas pricing.
    /// @param priceOracle_ Optional USD oracle; zero for min-fee-only deployments.
    /// @param defaultDepositFixedFee_ Default deposit fee floor in native wei.
    /// @param defaultDepositPercentageBps_ Default deposit percentage (FEE_DIVISOR scale).
    /// @param defaultDepositMaxFee_ Default deposit fee cap in native wei.
    /// @param defaultWithdrawFixedFee_ Default withdraw fee floor in native wei.
    /// @param defaultWithdrawPercentageBps_ Default withdraw percentage (FEE_DIVISOR scale).
    /// @param defaultWithdrawMaxFee_ Default withdraw fee cap in native wei.
    constructor(
        address initialOwner,
        address inbox_,
        uint256 cotiChainId_,
        address cotiMotherContract_,
        address podTokenImplementation_,
        address portalImplementation_,
        address feeRecipient_,
        address nativeToken_,
        address priceOracle_,
        uint256 defaultDepositFixedFee_,
        uint256 defaultDepositPercentageBps_,
        uint256 defaultDepositMaxFee_,
        uint256 defaultWithdrawFixedFee_,
        uint256 defaultWithdrawPercentageBps_,
        uint256 defaultWithdrawMaxFee_
    ) Ownable(initialOwner) {
        if (
            initialOwner == address(0) || inbox_ == address(0) || cotiChainId_ == 0
                || cotiMotherContract_ == address(0) || podTokenImplementation_ == address(0)
                || portalImplementation_ == address(0) || feeRecipient_ == address(0)
                || nativeToken_ == address(0)
        ) {
            revert InvalidAddress();
        }
        inbox = inbox_;
        cotiChainId = cotiChainId_;
        cotiMotherContract = cotiMotherContract_;
        podTokenImplementation = podTokenImplementation_;
        portalImplementation = portalImplementation_;
        feeRecipient = feeRecipient_;
        nativeToken = nativeToken_;
        priceOracle = IPodPriceOracle(priceOracle_);
        defaultDepositFeePacked = PrivacyPortalFeeLib.packFeeConfig(
            defaultDepositFixedFee_, defaultDepositPercentageBps_, defaultDepositMaxFee_
        );
        defaultWithdrawFeePacked = PrivacyPortalFeeLib.packFeeConfig(
            defaultWithdrawFixedFee_, defaultWithdrawPercentageBps_, defaultWithdrawMaxFee_
        );
        deployers[initialOwner] = true;
        emit DeployerUpdated(initialOwner, true);
        emit DefaultPortalFeeUpdated(true, defaultDepositFeePacked);
        emit DefaultPortalFeeUpdated(false, defaultWithdrawFeePacked);
        if (priceOracle_ != address(0)) {
            emit PriceOracleUpdated(address(0), priceOracle_);
        }
    }

    /// @notice Add or remove a portal deployer.
    function setDeployer(address deployer, bool allowed) external onlyOwner {
        if (deployer == address(0)) {
            revert InvalidAddress();
        }
        deployers[deployer] = allowed;
        emit DeployerUpdated(deployer, allowed);
    }

    /// @notice Set the global pause flag read by portals initialized from this factory.
    function setWithdrawalsPaused(bool paused) external onlyOwner {
        withdrawalsPaused = paused;
        emit WithdrawalsPausedUpdated(paused);
    }

    /// @notice Set the global deposit pause flag read by portals initialized from this factory.
    function setDepositsPaused(bool paused) external onlyOwner {
        depositsPaused = paused;
        emit DepositsPausedUpdated(paused);
    }

    /// @notice Pause or unpause both deposits and withdrawals (emergency circuit breaker).
    function setOperationsPaused(bool paused) external onlyOwner {
        withdrawalsPaused = paused;
        depositsPaused = paused;
        emit OperationsPausedUpdated(paused);
        emit WithdrawalsPausedUpdated(paused);
        emit DepositsPausedUpdated(paused);
    }

    /// @notice Update factory default deposit fee config.
    function setDefaultDepositFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external onlyOwner {
        bytes32 packed = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
        defaultDepositFeePacked = packed;
        emit DefaultPortalFeeUpdated(true, packed);
    }

    /// @notice Update factory default withdraw fee config.
    function setDefaultWithdrawFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee) external onlyOwner {
        bytes32 packed = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
        defaultWithdrawFeePacked = packed;
        emit DefaultPortalFeeUpdated(false, packed);
    }

    /// @notice Upgrade or disable the portal fee oracle.
    function setPriceOracle(address newOracle) external onlyOwner {
        address previous = address(priceOracle);
        priceOracle = IPodPriceOracle(newOracle);
        emit PriceOracleUpdated(previous, newOracle);
    }

    /// @inheritdoc IPrivacyPortalFactory
    function estimateDepositPortalFee(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 fee, bool usedDynamicPricing)
    {
        return _estimatePortalFee(defaultDepositFeePacked, underlying, amount, decimals);
    }

    /// @inheritdoc IPrivacyPortalFactory
    function estimateWithdrawPortalFee(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 fee, bool usedDynamicPricing)
    {
        return _estimatePortalFee(defaultWithdrawFeePacked, underlying, amount, decimals);
    }

    /// @inheritdoc IPrivacyPortalFactory
    function getDepositPortalFeeFloor(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 floor, uint128 maxFee)
    {
        return _portalFeeFloor(defaultDepositFeePacked, underlying, amount, decimals);
    }

    /// @inheritdoc IPrivacyPortalFactory
    function getWithdrawPortalFeeFloor(address underlying, uint256 amount, uint8 decimals)
        external
        view
        returns (uint256 floor, uint128 maxFee)
    {
        return _portalFeeFloor(defaultWithdrawFeePacked, underlying, amount, decimals);
    }

    /// @inheritdoc IPrivacyPortalFactory
    function getFeeConfig(bool isDeposit) external view returns (PortalFeeConfig memory config) {
        return PrivacyPortalFeeLib.decodeFeeConfig(
            isDeposit ? defaultDepositFeePacked : defaultWithdrawFeePacked
        );
    }

    /// @inheritdoc IPrivacyPortalFactory
    function decodeFeeConfig(bytes32 packed) external pure returns (PortalFeeConfig memory config) {
        return PrivacyPortalFeeLib.decodeFeeConfig(packed);
    }

    /// @notice Deploy a portal and pToken clone for an underlying token and register on the COTI mother ledger.
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

    function _estimatePortalFee(
        bytes32 packed,
        address underlying,
        uint256 amount,
        uint8 decimals
    ) private view returns (uint256 fee, bool usedDynamicPricing) {
        IPodPriceOracle oracle = priceOracle;
        if (address(oracle) == address(0)) {
            (uint96 fixedFee,,) = PrivacyPortalFeeLib.unpackFeeConfig(packed);
            return (fixedFee, false);
        }

        (uint256 nativeUsd, uint256 collateralUsd) =
            oracle.getLivePrices(nativeToken, underlying);
        return PrivacyPortalFeeLib.resolvePortalFee(
            packed,
            amount,
            decimals,
            collateralUsd,
            nativeUsd
        );
    }

    function _portalFeeFloor(bytes32 packed, address underlying, uint256 amount, uint8 decimals)
        private
        view
        returns (uint256 floor, uint128 maxFee)
    {
        (uint96 fixedFee, uint32 bps, uint128 max) = PrivacyPortalFeeLib.unpackFeeConfig(packed);
        maxFee = max;
        IPodPriceOracle oracle = priceOracle;
        if (address(oracle) == address(0) || bps == 0) {
            return (fixedFee, maxFee);
        }
        (uint256 nativeUsd, uint256 collateralUsd) =
            oracle.getLivePrices(nativeToken, underlying);
        (floor,) = PrivacyPortalFeeLib.resolvePortalFee(
            packed,
            amount,
            decimals,
            collateralUsd,
            nativeUsd
        );
    }

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
