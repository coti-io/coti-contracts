// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import "../../token/perc20/IPodERC20.sol";

/// @dev Clone-friendly mintable pToken mock for factory remount / deposit-withdraw tests.
contract MockPodErc20MintableForPortal is Initializable, Ownable {
    address public minter;
    uint8 public decimals;
    string public name;
    string public symbol;

    address public lastMintRecipient;
    uint256 public lastMintAmount;
    bytes32 public lastMintRequestId;
    address public lastTransferFrom;
    address public lastTransferTo;
    uint256 public lastTransferAmount;
    bytes32 public lastTransferRequestId;
    bytes public lastTransferCallbackData;

    mapping(bytes32 => IPodERC20.RequestStatus) private _requestStatus;

    error OnlyMinter(address caller);
    error InvalidMinter();

    event MinterUpdated(address indexed previousMinter, address indexed newMinter);

    constructor() Ownable(address(1)) {
        _disableInitializers();
    }

    function initialize(
        address _minter,
        address _owner,
        uint256,
        address,
        address,
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) external initializer {
        if (_minter == address(0) || _owner == address(0)) {
            revert InvalidMinter();
        }
        minter = _minter;
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        _transferOwnership(_owner);
    }

    function setMinter(address newMinter) external onlyOwner {
        if (newMinter == address(0)) {
            revert InvalidMinter();
        }
        address previous = minter;
        minter = newMinter;
        emit MinterUpdated(previous, newMinter);
    }

    function estimateFee()
        external
        pure
        returns (uint256 totalFeeWei, uint256 targetFeeWei, uint256 callbackFeeWei)
    {
        return (1000, 900, 100);
    }

    function mint(address to, uint256 amount, uint256)
        external
        payable
        returns (bytes32 requestId)
    {
        if (msg.sender != minter) {
            revert OnlyMinter(msg.sender);
        }
        lastMintRecipient = to;
        lastMintAmount = amount;
        requestId = keccak256(abi.encodePacked("mint", to, amount, block.number, address(this)));
        lastMintRequestId = requestId;
        _requestStatus[requestId] = IPodERC20.RequestStatus.Pending;
        return requestId;
    }

    function transferFromAndCallWithPermit(
        address from,
        address to,
        uint256 amount,
        IPodERC20.PublicPermit calldata,
        bytes calldata data,
        uint256
    ) external payable returns (bytes32 requestId) {
        lastTransferFrom = from;
        lastTransferTo = to;
        lastTransferAmount = amount;
        lastTransferCallbackData = data;
        requestId = keccak256(abi.encodePacked("transfer", from, to, amount, block.number, address(this)));
        lastTransferRequestId = requestId;
        _requestStatus[requestId] = IPodERC20.RequestStatus.Pending;
        return requestId;
    }

    function requests(bytes32 requestId) external view returns (IPodERC20.RequestRecord memory) {
        IPodERC20.RequestStatus status = _requestStatus[requestId];
        if (status == IPodERC20.RequestStatus.None) {
            status = IPodERC20.RequestStatus.Pending;
        }
        return IPodERC20.RequestRecord({
            status: status,
            recipientLocked: false,
            account: address(0),
            spender: address(0)
        });
    }

    function markLastMintSuccessful() external {
        _requestStatus[lastMintRequestId] = IPodERC20.RequestStatus.Success;
    }

    function markLastMintFailed() external {
        _requestStatus[lastMintRequestId] = IPodERC20.RequestStatus.SystemFailed;
    }

    function markLastTransferSuccessful() external {
        _requestStatus[lastTransferRequestId] = IPodERC20.RequestStatus.Success;
    }

    function burn(uint256, uint256) external payable returns (bytes32 requestId) {
        requestId = keccak256(abi.encodePacked("burn", msg.value, block.number));
        _requestStatus[requestId] = IPodERC20.RequestStatus.Pending;
    }

    function configure(address, address) external onlyOwner {}
}
