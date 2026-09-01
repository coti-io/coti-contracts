// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Pausable.sol";
import "../PodERC20.sol";

/// @title PodERC20Pausable
/// @notice OpenZeppelin-style extension: gates async user operations while paused via {_sendPodTwoWay}.
/// @dev Mirrors {ERC20Pausable}: no public {pause}/{unpause}; concrete tokens must expose them with access control.
///      Not inherited by {PodErc20Mintable} (Privacy Portal pTokens stay unpausable at the token layer).
abstract contract PodERC20Pausable is PodERC20, Pausable {
    /// @inheritdoc PodERC20
    function _sendPodTwoWay(
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei,
        IInbox.MpcMethodCall memory mpcMethodCall,
        bytes4 callbackSelector_,
        bytes4 errorSelector_
    ) internal virtual override returns (bytes32) {
        _requireNotPaused();
        return super._sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            callbackSelector_,
            errorSelector_
        );
    }
}
