// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../extensions/PodERC20Burnable.sol";
import "../extensions/PodERC20Pausable.sol";
import "../../../IInbox.sol";

/// @title PodERC20PausableMock
/// @notice Test/deploy helper combining {PodERC20Burnable} and {PodERC20Pausable} with owner-gated pause controls.
/// @dev Not used by {PrivacyPortalFactory}; demonstrates the OZ pattern where the concrete token exposes {pause}/{unpause}.
contract PodERC20PausableMock is PodERC20Pausable, PodERC20Burnable {
    constructor(
        uint256 _cotiChainId,
        address _inbox,
        address _cotiSideContract,
        string memory _name,
        string memory _symbol
    ) PodERC20(_cotiChainId, _inbox, _cotiSideContract, _name, _symbol) {}

    function _sendPodTwoWay(
        uint256 totalValueWei,
        uint256 callbackFeeLocalWei,
        IInbox.MpcMethodCall memory mpcMethodCall,
        bytes4 callbackSelector_,
        bytes4 errorSelector_
    ) internal override(PodERC20, PodERC20Pausable) returns (bytes32) {
        return PodERC20Pausable._sendPodTwoWay(
            totalValueWei,
            callbackFeeLocalWei,
            mpcMethodCall,
            callbackSelector_,
            errorSelector_
        );
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
