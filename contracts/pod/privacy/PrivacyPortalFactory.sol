// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

import "../IInbox.sol";
import "../token/perc20/IPodERC20.sol";
import "../token/perc20/PodErc20MintableInitializable.sol";
import "../token/perc20/cotiside/PodErc20CotiMother.sol";
import "./IPrivacyPortal.sol";
import "./IPrivacyPortalFactory.sol";
import "./IPodPriceOracle.sol";
import "./PrivacyPortalFeeLib.sol";

/// @title PrivacyPortalFactory
/// @notice Deploys one-shot minimal-clone portals and pTokens for public ERC20 collateral.
/// @dev Governance uses OpenZeppelin {AccessControlEnumerable}: {DEFAULT_ADMIN_ROLE} for admin actions,
///      {OPERATOR_ROLE} for default fee updates. Manage roles via {grantRole} and {revokeRole}.
contract PrivacyPortalFactory is IPrivacyPortalFactory, AccessControlEnumerable {
    using PrivacyPortalFeeLib for bytes32;

    /// @notice Operator role for routine fee-parameter updates (mirrors Privacy Bridge).
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Source-chain inbox used by pToken clones and registration messages.
    address public inbox;
    /// @notice COTI chain id used by pToken clones for remote MPC execution.
    uint256 public cotiChainId;
    /// @notice Unified COTI-side pToken ledger all clones talk to.
    address public cotiMotherContract;
    /// @notice Clone implementation for source-chain pTokens.
    address public immutable podTokenImplementation;
    /// @notice Clone implementation for portals.
    address public immutable portalImplementation;
    /// @notice Recipient of swept portal protocol fees from all portals created here.
    address public feeRecipient;
    /// @notice Catastrophe rescue destination for all portals created here (pause + owner rescue).
    address public rescueRecipient;
    /// @notice Wrapped native token on this chain (WETH/WAVAX) for portal gas fee pricing.
    address public immutable nativeToken;
    /// @notice Global flag exposed through the pause-controller interface for all portals created here.
    bool public withdrawalsPaused;
    /// @notice Global flag exposed through the pause-controller interface for deposits on factory-created portals.
    bool public depositsPaused;

    /// @notice Optional USD oracle for dynamic portal fees; zero disables dynamic pricing.
    IPodPriceOracle public priceOracle;
    /// @notice Admin knob mirroring Privacy Bridge freshness policy.
    /// @dev Current {IPodPriceOracle} adapters already return `0` when stale (fixed-fee fallback). Kept for ops parity
    ///      and future timestamp-aware fee binding; not enforced in fee math today.
    uint256 public constant DEFAULT_MAX_ORACLE_AGE = 30 minutes + 5 minutes;
    uint256 public maxOracleAge;
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
    /// @notice Addresses blocked from deposits and withdrawals on factory-created portals.
    mapping(address => bool) public blacklisted;

    /// @notice Address added to the factory blacklist.
    event Blacklisted(address indexed account, address indexed by);
    /// @notice Address removed from the factory blacklist.
    event UnBlacklisted(address indexed account, address indexed by);
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
    /// @notice Max oracle age admin knob updated (see {maxOracleAge} docs).
    event MaxOracleAgeUpdated(uint256 previousAge, uint256 newAge);
    /// @notice Inbox / COTI mother routing updated for newly created portals and registration messages.
    event RoutingUpdated(address indexed inbox, uint256 cotiChainId, address indexed cotiMotherContract);
    /// @notice Fee recipient updated for swept portal protocol fees.
    event FeeRecipientUpdated(address indexed previousRecipient, address indexed newRecipient);
    /// @notice Rescue recipient updated for paused portal rescue paths.
    event RescueRecipientUpdated(address indexed previousRecipient, address indexed newRecipient);

    /// @notice Caller is not an allowlisted deployer.
    error OnlyDeployer(address caller);
    /// @notice A required address was zero.
    error InvalidAddress();
    /// @notice A portal already exists for the underlying token.
    error PortalAlreadyExists(address underlying, address portal);
    /// @notice pToken is not registered to a portal created by this factory.
    error UnknownPToken(address pToken);
    /// @notice Oracle is not configured.
    error OracleNotConfigured();
    /// @notice No {DEFAULT_ADMIN_ROLE} holder is configured.
    error AdminNotConfigured();
    /// @notice maxOracleAge cannot be zero.
    error OracleMaxAgeZeroDisallowed();

    /// @notice Restrict a function to an allowlisted deployer.
    modifier onlyDeployer() {
        if (!deployers[msg.sender]) {
            revert OnlyDeployer(msg.sender);
        }
        _;
    }

    /// @param initialOwner Initial {DEFAULT_ADMIN_ROLE} holder and deployer.
    /// @param inbox_ Source-chain inbox used by pToken clones.
    /// @param cotiChainId_ COTI chain id used by pToken clones.
    /// @param cotiMotherContract_ Unified COTI-side pToken ledger.
    /// @param podTokenImplementation_ Clone implementation for source-chain pTokens.
    /// @param portalImplementation_ Clone implementation for portals.
    /// @param feeRecipient_ Recipient of swept portal protocol fees.
    /// @param rescueRecipient_ Catastrophe rescue destination for portals from this factory.
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
        address rescueRecipient_,
        address nativeToken_,
        address priceOracle_,
        uint256 defaultDepositFixedFee_,
        uint256 defaultDepositPercentageBps_,
        uint256 defaultDepositMaxFee_,
        uint256 defaultWithdrawFixedFee_,
        uint256 defaultWithdrawPercentageBps_,
        uint256 defaultWithdrawMaxFee_
    ) {
        if (
            initialOwner == address(0) || inbox_ == address(0) || cotiChainId_ == 0
                || cotiMotherContract_ == address(0) || podTokenImplementation_ == address(0)
                || portalImplementation_ == address(0) || feeRecipient_ == address(0)
                || rescueRecipient_ == address(0) || nativeToken_ == address(0)
        ) {
            revert InvalidAddress();
        }
        inbox = inbox_;
        cotiChainId = cotiChainId_;
        cotiMotherContract = cotiMotherContract_;
        podTokenImplementation = podTokenImplementation_;
        portalImplementation = portalImplementation_;
        feeRecipient = feeRecipient_;
        rescueRecipient = rescueRecipient_;
        nativeToken = nativeToken_;
        priceOracle = IPodPriceOracle(priceOracle_);
        maxOracleAge = DEFAULT_MAX_ORACLE_AGE;
        defaultDepositFeePacked = PrivacyPortalFeeLib.packFeeConfig(
            defaultDepositFixedFee_, defaultDepositPercentageBps_, defaultDepositMaxFee_
        );
        defaultWithdrawFeePacked = PrivacyPortalFeeLib.packFeeConfig(
            defaultWithdrawFixedFee_, defaultWithdrawPercentageBps_, defaultWithdrawMaxFee_
        );
        deployers[initialOwner] = true;
        emit DeployerUpdated(initialOwner, true);
        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
        _grantRole(OPERATOR_ROLE, initialOwner);
        emit DefaultPortalFeeUpdated(true, defaultDepositFeePacked);
        emit DefaultPortalFeeUpdated(false, defaultWithdrawFeePacked);
        if (priceOracle_ != address(0)) {
            emit PriceOracleUpdated(address(0), priceOracle_);
        }
    }

    /// @notice Primary factory admin: first holder of {DEFAULT_ADMIN_ROLE}.
    /// @dev Mirrors `Ownable.owner()` for tooling compatibility. When multiple admins exist,
    ///      returns `getRoleMember(DEFAULT_ADMIN_ROLE, 0)` (enumeration order).
    function owner() external view returns (address) {
        if (getRoleMemberCount(DEFAULT_ADMIN_ROLE) == 0) {
            revert AdminNotConfigured();
        }
        return getRoleMember(DEFAULT_ADMIN_ROLE, 0);
    }

    /// @notice Add an address to the factory blacklist, blocking deposits and withdrawals on all portals here.
    function addToBlacklist(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (account == address(0)) {
            revert InvalidAddress();
        }
        blacklisted[account] = true;
        emit Blacklisted(account, msg.sender);
    }

    /// @notice Remove an address from the factory blacklist.
    function removeFromBlacklist(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (account == address(0)) {
            revert InvalidAddress();
        }
        blacklisted[account] = false;
        emit UnBlacklisted(account, msg.sender);
    }

    /// @notice Add or remove a portal deployer.
    function setDeployer(address deployer, bool allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (deployer == address(0)) {
            revert InvalidAddress();
        }
        deployers[deployer] = allowed;
        emit DeployerUpdated(deployer, allowed);
    }

    /// @notice Admin: rotate inbox, COTI chain id, and mother ledger used for new portals / registration.
    /// @dev Existing pToken clones keep their peer until {configurePToken} (factory is their Ownable owner).
    function configureRouting(address inbox_, uint256 cotiChainId_, address cotiMotherContract_)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (inbox_ == address(0) || cotiChainId_ == 0 || cotiMotherContract_ == address(0)) {
            revert InvalidAddress();
        }
        inbox = inbox_;
        cotiChainId = cotiChainId_;
        cotiMotherContract = cotiMotherContract_;
        emit RoutingUpdated(inbox_, cotiChainId_, cotiMotherContract_);
    }

    /// @notice Admin: rotate inbox / COTI peer on an existing factory-deployed pToken clone ({cotiChainId} is immutable on the token).
    function configurePToken(address pToken_, address inbox_, address cotiSideContract_)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (portalForPToken[pToken_] == address(0)) {
            revert UnknownPToken(pToken_);
        }
        IPodERC20(pToken_).configure(inbox_, cotiSideContract_);
    }

    /// @notice Admin: transfer Ownable of a factory-deployed pToken (e.g. hand off after launch).
    function transferPTokenOwnership(address pToken_, address newOwner_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (portalForPToken[pToken_] == address(0)) {
            revert UnknownPToken(pToken_);
        }
        if (newOwner_ == address(0)) {
            revert InvalidAddress();
        }
        Ownable(pToken_).transferOwnership(newOwner_);
    }

    /// @notice Admin: rotate the recipient of swept portal protocol fees.
    function setFeeRecipient(address feeRecipient_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (feeRecipient_ == address(0)) {
            revert InvalidAddress();
        }
        address previous = feeRecipient;
        feeRecipient = feeRecipient_;
        emit FeeRecipientUpdated(previous, feeRecipient_);
    }

    /// @notice Admin: rotate the catastrophe rescue destination used by all portals from this factory.
    function setRescueRecipient(address rescueRecipient_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (rescueRecipient_ == address(0)) {
            revert InvalidAddress();
        }
        address previous = rescueRecipient;
        rescueRecipient = rescueRecipient_;
        emit RescueRecipientUpdated(previous, rescueRecipient_);
    }

    /// @notice Set the global pause flag read by portals initialized from this factory.
    function setWithdrawalsPaused(bool paused) external onlyRole(DEFAULT_ADMIN_ROLE) {
        withdrawalsPaused = paused;
        emit WithdrawalsPausedUpdated(paused);
    }

    /// @notice Set the global deposit pause flag read by portals initialized from this factory.
    function setDepositsPaused(bool paused) external onlyRole(DEFAULT_ADMIN_ROLE) {
        depositsPaused = paused;
        emit DepositsPausedUpdated(paused);
    }

    /// @notice Pause or unpause both deposits and withdrawals (emergency circuit breaker).
    function setOperationsPaused(bool paused) external onlyRole(DEFAULT_ADMIN_ROLE) {
        withdrawalsPaused = paused;
        depositsPaused = paused;
        emit OperationsPausedUpdated(paused);
        emit WithdrawalsPausedUpdated(paused);
        emit DepositsPausedUpdated(paused);
    }

    /// @notice Update factory default deposit fee config.
    function setDefaultDepositFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee)
        external
        onlyRole(OPERATOR_ROLE)
    {
        bytes32 packed = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
        defaultDepositFeePacked = packed;
        emit DefaultPortalFeeUpdated(true, packed);
    }

    /// @notice Update factory default withdraw fee config.
    function setDefaultWithdrawFee(uint256 fixedFee, uint256 percentageBps, uint256 maxFee)
        external
        onlyRole(OPERATOR_ROLE)
    {
        bytes32 packed = PrivacyPortalFeeLib.packFeeConfig(fixedFee, percentageBps, maxFee);
        defaultWithdrawFeePacked = packed;
        emit DefaultPortalFeeUpdated(false, packed);
    }

    /// @notice Upgrade or disable the portal fee oracle.
    function setPriceOracle(address newOracle) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address previous = address(priceOracle);
        priceOracle = IPodPriceOracle(newOracle);
        emit PriceOracleUpdated(previous, newOracle);
    }

    /// @notice Set max oracle age (ops parity with Privacy Bridge). Zero disallowed.
    function setMaxOracleAge(uint256 maxOracleAge_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (maxOracleAge_ == 0) {
            revert OracleMaxAgeZeroDisallowed();
        }
        uint256 previous = maxOracleAge;
        maxOracleAge = maxOracleAge_;
        emit MaxOracleAgeUpdated(previous, maxOracleAge_);
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

        // Factory retains Ownable on the pToken so admins can {configurePToken} after inbox / mother upgrades.
        // Portal minter is the portal; portal Ownable is `portalOwner`.
        PodErc20MintableInitializable(payable(pToken)).initialize(
            portal,
            address(this),
            cotiChainId,
            inbox,
            cotiMotherContract,
            name,
            symbol,
            decimals
        );
        IPrivacyPortal(portal).initialize(
            portalOwner, underlying, pToken, decimals, nativeWrappedUnderlying, address(this)
        );

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
