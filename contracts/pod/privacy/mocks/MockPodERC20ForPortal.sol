// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../token/perc20/IPodERC20.sol";

/// @dev Lightweight pToken stand-in for PrivacyPortal unit tests.
contract MockPodERC20ForPortal {
    address public lastMintRecipient;
    uint256 public lastMintAmount;
    uint256 public lastMintValue;
    uint256 public lastMintCallbackFee;

    address public lastTransferFrom;
    address public lastTransferTo;
    uint256 public lastTransferAmount;
    uint256 public lastTransferValue;
    uint256 public lastTransferCallbackFee;
    bytes public lastTransferCallbackData;

    bytes32 public lastTransferRequestId;
    uint256 public burnedAmount;
    uint256 public lastBurnValue;
    uint256 public lastBurnCallbackFee;

    bool public burnShouldRevert;
    IPodERC20.RequestStatus private _lastTransferStatus;

    function estimateFee()
        external
        pure
        returns (uint256 totalFeeWei, uint256 targetFeeWei, uint256 callbackFeeWei)
    {
        return (1000, 900, 100);
    }

    function mint(address to, uint256 amount, uint256 callbackFeeLocalWei)
        external
        payable
        returns (bytes32 requestId)
    {
        lastMintRecipient = to;
        lastMintAmount = amount;
        lastMintValue = msg.value;
        lastMintCallbackFee = callbackFeeLocalWei;
        requestId = keccak256(abi.encodePacked("mint", to, amount, block.number));
        return requestId;
    }

    function transferFromAndCallWithPermit(
        address from,
        address to,
        uint256 amount,
        IPodERC20.PublicPermit calldata,
        bytes calldata data,
        uint256 callbackFeeLocalWei
    ) external payable returns (bytes32 requestId) {
        lastTransferFrom = from;
        lastTransferTo = to;
        lastTransferAmount = amount;
        lastTransferValue = msg.value;
        lastTransferCallbackFee = callbackFeeLocalWei;
        lastTransferCallbackData = data;
        _lastTransferStatus = IPodERC20.RequestStatus.Pending;
        requestId = keccak256(abi.encodePacked("transfer", from, to, amount, block.number));
        lastTransferRequestId = requestId;
        return requestId;
    }

    function requests(bytes32 requestId) external view returns (IPodERC20.RequestStatus) {
        if (requestId == lastTransferRequestId && _lastTransferStatus == IPodERC20.RequestStatus.Success) {
            return IPodERC20.RequestStatus.Success;
        }
        if (requestId == lastTransferRequestId) {
            return _lastTransferStatus;
        }
        return IPodERC20.RequestStatus.None;
    }

    function balanceOf(address) external pure returns (uint256) {
        return type(uint256).max;
    }

    function burn(uint256 amount, uint256 callbackFeeLocalWei) external payable returns (bytes32 requestId) {
        if (burnShouldRevert) {
            revert("MockPodERC20ForPortal: burn failed");
        }
        burnedAmount += amount;
        lastBurnValue = msg.value;
        lastBurnCallbackFee = callbackFeeLocalWei;
        return keccak256(abi.encodePacked("burn", amount, block.number));
    }

    function triggerLastTransferCallback() external {
        require(lastTransferCallbackData.length >= 4, "no callback");
        (bool ok,) = lastTransferTo.call(lastTransferCallbackData);
        require(ok, "callback failed");
    }

    function markLastTransferSuccessful() external {
        _lastTransferStatus = IPodERC20.RequestStatus.Success;
    }

    function setBurnShouldRevert(bool shouldRevert) external {
        burnShouldRevert = shouldRevert;
    }
}
