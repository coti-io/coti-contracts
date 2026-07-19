// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../token/perc20/IPodERC20.sol";

/// @dev Lightweight pToken stand-in for PrivacyPortal unit tests.
contract MockPodERC20ForPortal {
    address public lastMintRecipient;
    uint256 public lastMintAmount;
    uint256 public lastMintValue;
    uint256 public lastMintCallbackFee;
    bytes32 public lastMintRequestId;
    IPodERC20.RequestStatus private _lastMintStatus;

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

    mapping(bytes32 => IPodERC20.RequestStatus) private _requestStatus;

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
        lastMintRequestId = requestId;
        _lastMintStatus = IPodERC20.RequestStatus.Pending;
        _requestStatus[requestId] = IPodERC20.RequestStatus.Pending;
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
        _requestStatus[requestId] = IPodERC20.RequestStatus.Pending;
        return requestId;
    }

    function requests(bytes32 requestId) external view returns (IPodERC20.RequestRecord memory) {
        IPodERC20.RequestStatus status = _requestStatus[requestId];
        if (status == IPodERC20.RequestStatus.None) {
            if (requestId == lastTransferRequestId) {
                status = _lastTransferStatus;
            } else if (requestId == lastMintRequestId) {
                status = _lastMintStatus;
            }
        }
        return IPodERC20.RequestRecord({
            status: status,
            recipientLocked: false,
            account: address(0),
            spender: address(0)
        });
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
        if (lastTransferRequestId != bytes32(0)) {
            _requestStatus[lastTransferRequestId] = IPodERC20.RequestStatus.Success;
        }
    }

    function markLastTransferFailed() external {
        _lastTransferStatus = IPodERC20.RequestStatus.Failed;
        if (lastTransferRequestId != bytes32(0)) {
            _requestStatus[lastTransferRequestId] = IPodERC20.RequestStatus.Failed;
        }
    }

    function markLastTransferSystemFailed() external {
        _lastTransferStatus = IPodERC20.RequestStatus.SystemFailed;
        if (lastTransferRequestId != bytes32(0)) {
            _requestStatus[lastTransferRequestId] = IPodERC20.RequestStatus.SystemFailed;
        }
    }

    function markLastMintSuccessful() external {
        _lastMintStatus = IPodERC20.RequestStatus.Success;
        if (lastMintRequestId != bytes32(0)) {
            _requestStatus[lastMintRequestId] = IPodERC20.RequestStatus.Success;
        }
    }

    function markLastMintFailed() external {
        _lastMintStatus = IPodERC20.RequestStatus.SystemFailed;
        if (lastMintRequestId != bytes32(0)) {
            _requestStatus[lastMintRequestId] = IPodERC20.RequestStatus.SystemFailed;
        }
    }

    /// @dev Simulate app `raise` on mint (not refundable via portal).
    function markLastMintRaised() external {
        _lastMintStatus = IPodERC20.RequestStatus.Failed;
        if (lastMintRequestId != bytes32(0)) {
            _requestStatus[lastMintRequestId] = IPodERC20.RequestStatus.Failed;
        }
    }

    function setBurnShouldRevert(bool shouldRevert) external {
        burnShouldRevert = shouldRevert;
    }
}
