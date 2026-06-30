// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

import "../IInbox.sol";
import "../InboxUser.sol";

/// @title PodUser
/// @notice POD base: COTI chain ID, MPC executor address, and owner-gated {configure}.
abstract contract PodUser is InboxUser, Ownable {
    /// @notice Default MPC error callback surfaced from the outbox.
    event ErrorRemoteCall(bytes32 requestId, uint256 code, string message);

    /// @notice Inbox callback remote sender did not match configured COTI MPC executor.
    error OnlyMpcExecutor(uint256 remoteChainId, address remoteContract);

    /// @notice COTI-side MPC executor target.
    address internal mpcExecutorAddress = 0x0000000000000000000000000000000000000000;
    /// @notice COTI chain id used for MPC requests.
    uint256 internal cotiChainId = 2632500;

    /// @param initialOwner Initial owner for configuration.
    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @dev Internal COTI routing; use {configure} from outside this contract.
    /// @param _mpcExecutorAddress COTI-side MPC executor address.
    /// @param _cotiChainId COTI chain id.
    function configureCoti(address _mpcExecutorAddress, uint256 _cotiChainId) internal virtual {
        mpcExecutorAddress = _mpcExecutorAddress;
        cotiChainId = _cotiChainId;
    }

    /// @notice Restrict a function to inbox callbacks from the configured COTI MPC executor.
    /// @dev Reverts unless `msg.sender` is the inbox and the remote sender matches {cotiChainId} and {mpcExecutorAddress}.
    ///      For callbacks that only need inbox verification, use {onlyInbox} from {InboxUser} instead.
    modifier onlyMpcExecutor() {
        if (msg.sender != address(inbox)) {
            revert OnlyInbox(msg.sender);
        }
        (uint256 remoteChainId, address remoteContract) = inbox.inboxMsgSender();
        if (remoteChainId != cotiChainId || remoteContract != mpcExecutorAddress) {
            revert OnlyMpcExecutor(remoteChainId, remoteContract);
        }
        _;
    }

    /// @notice Owner-only: set inbox when `inbox_ != address(0)`; always updates COTI executor and chain id.
    /// @param inbox_ New inbox address, or zero to leave the existing inbox unchanged.
    /// @param mpcExecutor_ New COTI-side MPC executor address.
    /// @param cotiChainId_ New COTI chain id.
    function configure(address inbox_, address mpcExecutor_, uint256 cotiChainId_) external onlyOwner {
        if (inbox_ != address(0)) {
            setInbox(inbox_);
        }
        configureCoti(mpcExecutor_, cotiChainId_);
    }
}
