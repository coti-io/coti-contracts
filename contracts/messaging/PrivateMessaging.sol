// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../utils/mpc/MpcCore.sol";

contract PrivateMessaging {
    error NotOwner();
    error InvalidEpochDuration();
    error InvalidRecipient();
    error MessageNotFound();
    error UnauthorizedViewer();
    error ZeroValue();
    error InvalidChunkCount();
    error ChunkTooLarge();
    error ChunkOutOfBounds();
    error EpochStillActive();
    error NothingToClaim();
    error AlreadyClaimed();
    error NativeTransferFailed();
    error PastEpochFundingNotAllowed();

    event MessageSent(
        uint256 indexed messageId,
        address indexed from,
        address indexed to,
        uint256 epoch
    );
    event RewardFunded(uint256 indexed epoch, address indexed funder, uint256 amount);
    event RewardClaimed(uint256 indexed epoch, address indexed agent, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    struct MessageRecord {
        bool exists;
        address from;
        address to;
        uint64 timestamp;
        uint64 epoch;
        uint32 chunkCount;
    }

    struct MessageView {
        uint256 id;
        address from;
        address to;
        uint64 timestamp;
        uint64 epoch;
        uint32 chunkCount;
        ctString ciphertext;
    }

    uint8 public constant MAX_CHUNK_CELLS = 3;
    uint32 public constant MAX_CHUNKS_PER_MESSAGE = 64;

    address public owner;
    uint64 public immutable epochDuration;
    uint64 public immutable genesisTimestamp;

    uint256 private _nextMessageId;

    mapping(uint256 => MessageRecord) private _messages;
    mapping(uint256 => mapping(uint256 => ctString)) private _networkCiphertexts;
    mapping(uint256 => mapping(uint256 => ctString)) private _senderCiphertexts;
    mapping(uint256 => mapping(uint256 => ctString)) private _recipientCiphertexts;
    mapping(address => uint256[]) private _inboxMessageIds;
    mapping(address => uint256[]) private _sentMessageIds;

    mapping(uint256 => mapping(address => uint256)) public epochUsageUnits;
    mapping(uint256 => uint256) public epochTotalUsageUnits;
    mapping(uint256 => uint256) public epochRewardPool;
    mapping(uint256 => uint256) public epochClaimedAmount;
    mapping(uint256 => uint256) public epochClaimedUsageUnits;
    mapping(uint256 => mapping(address => bool)) public epochHasClaimed;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        _;
    }

    constructor(uint64 epochDurationSeconds) payable {
        if (epochDurationSeconds == 0) {
            revert InvalidEpochDuration();
        }

        owner = msg.sender;
        epochDuration = epochDurationSeconds;
        genesisTimestamp = uint64(block.timestamp);

        emit OwnershipTransferred(address(0), msg.sender);

        if (msg.value > 0) {
            _fundEpoch(currentEpoch(), msg.sender, msg.value);
        }
    }

    receive() external payable {
        _fundEpoch(currentEpoch(), msg.sender, msg.value);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert InvalidRecipient();
        }

        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function currentEpoch() public view returns (uint256) {
        return (block.timestamp - genesisTimestamp) / epochDuration;
    }

    function epochForTimestamp(uint256 timestamp) public view returns (uint256) {
        if (timestamp < genesisTimestamp) {
            return 0;
        }

        return (timestamp - genesisTimestamp) / epochDuration;
    }

    function fundEpoch(uint256 epoch) external payable {
        if (msg.value == 0) {
            revert ZeroValue();
        }

        if (epoch < currentEpoch()) {
            revert PastEpochFundingNotAllowed();
        }

        _fundEpoch(epoch, msg.sender, msg.value);
    }

    function sendMessage(address to, itString calldata encryptedMessage) external returns (uint256 messageId) {
        if (to == address(0) || to == msg.sender) {
            revert InvalidRecipient();
        }

        uint256 usageUnits = _validateEncryptedChunk(encryptedMessage);

        messageId = _createMessageRecord(msg.sender, to, 1);

        gtString memory validatedMessage = MpcCore.validateCiphertext(encryptedMessage);
        _storeChunkCiphertexts(
            messageId,
            0,
            MpcCore.offBoard(validatedMessage),
            MpcCore.offBoardToUser(validatedMessage, msg.sender),
            MpcCore.offBoardToUser(validatedMessage, to)
        );

        _addEpochUsage(_messages[messageId].epoch, msg.sender, usageUnits);
    }

    function sendMultipartMessage(address to, itString[] calldata encryptedChunks)
        external
        returns (uint256 messageId)
    {
        if (to == address(0) || to == msg.sender) {
            revert InvalidRecipient();
        }

        uint256 chunkCount = encryptedChunks.length;
        if (chunkCount == 0 || chunkCount > MAX_CHUNKS_PER_MESSAGE) {
            revert InvalidChunkCount();
        }

        uint256 usageUnits;
        for (uint256 i = 0; i < chunkCount; i++) {
            usageUnits += _validateEncryptedChunk(encryptedChunks[i]);
        }

        messageId = _createMessageRecord(msg.sender, to, chunkCount);

        for (uint256 i = 0; i < chunkCount; i++) {
            gtString memory validatedMessage = MpcCore.validateCiphertext(encryptedChunks[i]);
            _storeChunkCiphertexts(
                messageId,
                i,
                MpcCore.offBoard(validatedMessage),
                MpcCore.offBoardToUser(validatedMessage, msg.sender),
                MpcCore.offBoardToUser(validatedMessage, to)
            );
        }

        _addEpochUsage(_messages[messageId].epoch, msg.sender, usageUnits);
    }

    function getMessageMetadata(uint256 messageId)
        external
        view
        returns (address from, address to, uint64 timestamp, uint64 epoch)
    {
        MessageRecord storage record = _requireMessage(messageId);
        return (record.from, record.to, record.timestamp, record.epoch);
    }

    function getMessage(uint256 messageId) external view returns (MessageView memory messageView) {
        MessageRecord storage record = _requireMessage(messageId);
        ctString memory ciphertext = _messageCiphertextForViewer(messageId, record, msg.sender, 0);

        return MessageView({
            id: messageId,
            from: record.from,
            to: record.to,
            timestamp: record.timestamp,
            epoch: record.epoch,
            chunkCount: record.chunkCount,
            ciphertext: ciphertext
        });
    }

    function getMessageChunkCount(uint256 messageId) external view returns (uint256 chunkCount) {
        MessageRecord storage record = _requireMessage(messageId);
        return record.chunkCount;
    }

    function getMessageChunk(uint256 messageId, uint256 chunkIndex)
        external
        view
        returns (ctString memory ciphertext)
    {
        MessageRecord storage record = _requireMessage(messageId);
        return _messageCiphertextForViewer(messageId, record, msg.sender, chunkIndex);
    }

    function getSenderCiphertext(uint256 messageId) external view returns (ctString memory ciphertext) {
        _requireMessage(messageId);
        return _senderCiphertexts[messageId][0];
    }

    function getSenderChunkCiphertext(uint256 messageId, uint256 chunkIndex)
        external
        view
        returns (ctString memory ciphertext)
    {
        MessageRecord storage record = _requireMessage(messageId);
        _requireChunkIndex(record, chunkIndex);
        return _senderCiphertexts[messageId][chunkIndex];
    }

    function getRecipientCiphertext(uint256 messageId) external view returns (ctString memory ciphertext) {
        _requireMessage(messageId);
        return _recipientCiphertexts[messageId][0];
    }

    function getRecipientChunkCiphertext(uint256 messageId, uint256 chunkIndex)
        external
        view
        returns (ctString memory ciphertext)
    {
        MessageRecord storage record = _requireMessage(messageId);
        _requireChunkIndex(record, chunkIndex);
        return _recipientCiphertexts[messageId][chunkIndex];
    }

    function getNetworkCiphertext(uint256 messageId) external view returns (ctString memory ciphertext) {
        _requireMessage(messageId);
        return _networkCiphertexts[messageId][0];
    }

    function getNetworkChunkCiphertext(uint256 messageId, uint256 chunkIndex)
        external
        view
        returns (ctString memory ciphertext)
    {
        MessageRecord storage record = _requireMessage(messageId);
        _requireChunkIndex(record, chunkIndex);
        return _networkCiphertexts[messageId][chunkIndex];
    }

    function inboxCount(address account) external view returns (uint256) {
        return _inboxMessageIds[account].length;
    }

    function sentCount(address account) external view returns (uint256) {
        return _sentMessageIds[account].length;
    }

    function getInboxPage(
        address account,
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory messageIds) {
        return _slice(_inboxMessageIds[account], offset, limit);
    }

    function getSentPage(
        address account,
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory messageIds) {
        return _slice(_sentMessageIds[account], offset, limit);
    }

    function pendingRewards(uint256 epoch, address agent) public view returns (uint256) {
        if (epoch >= currentEpoch() || epochHasClaimed[epoch][agent]) {
            return 0;
        }

        uint256 usage = epochUsageUnits[epoch][agent];
        uint256 totalUsage = epochTotalUsageUnits[epoch];
        uint256 rewardPool = epochRewardPool[epoch];

        if (usage == 0 || totalUsage == 0 || rewardPool == 0) {
            return 0;
        }

        uint256 claimedUsage = epochClaimedUsageUnits[epoch];
        uint256 claimedAmount = epochClaimedAmount[epoch];

        uint256 remainingUsage = totalUsage - claimedUsage;
        uint256 remainingPool = rewardPool - claimedAmount;

        if (usage == remainingUsage) {
            return remainingPool;
        }

        return (remainingPool * usage) / remainingUsage;
    }

    function claimRewards(uint256 epoch) external returns (uint256 amount) {
        if (epoch >= currentEpoch()) {
            revert EpochStillActive();
        }

        if (epochHasClaimed[epoch][msg.sender]) {
            revert AlreadyClaimed();
        }

        amount = pendingRewards(epoch, msg.sender);
        if (amount == 0) {
            revert NothingToClaim();
        }

        uint256 usage = epochUsageUnits[epoch][msg.sender];

        epochHasClaimed[epoch][msg.sender] = true;
        epochClaimedUsageUnits[epoch] += usage;
        epochClaimedAmount[epoch] += amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) {
            revert NativeTransferFailed();
        }

        emit RewardClaimed(epoch, msg.sender, amount);
    }

    function getEpochSummary(uint256 epoch)
        external
        view
        returns (
            uint256 totalUsageUnits,
            uint256 rewardPool,
            uint256 claimedAmount,
            uint256 claimedUsageUnits
        )
    {
        return (
            epochTotalUsageUnits[epoch],
            epochRewardPool[epoch],
            epochClaimedAmount[epoch],
            epochClaimedUsageUnits[epoch]
        );
    }

    function _fundEpoch(uint256 epoch, address funder, uint256 amount) internal {
        if (amount == 0) {
            revert ZeroValue();
        }

        epochRewardPool[epoch] += amount;
        emit RewardFunded(epoch, funder, amount);
    }

    function _createMessageRecord(
        address from,
        address to,
        uint256 chunkCount
    ) internal returns (uint256 messageId) {
        uint256 epoch = currentEpoch();
        messageId = _nextMessageId++;

        MessageRecord storage record = _messages[messageId];
        record.exists = true;
        record.from = from;
        record.to = to;
        record.timestamp = uint64(block.timestamp);
        record.epoch = uint64(epoch);
        record.chunkCount = uint32(chunkCount);

        _sentMessageIds[from].push(messageId);
        _inboxMessageIds[to].push(messageId);

        emit MessageSent(messageId, from, to, epoch);
    }

    function _addEpochUsage(uint256 epoch, address from, uint256 usageUnits) internal {
        epochUsageUnits[epoch][from] += usageUnits;
        epochTotalUsageUnits[epoch] += usageUnits;
    }

    function _storeChunkCiphertexts(
        uint256 messageId,
        uint256 chunkIndex,
        ctString memory networkCiphertext,
        ctString memory senderCiphertext,
        ctString memory recipientCiphertext
    ) internal {
        _networkCiphertexts[messageId][chunkIndex] = networkCiphertext;
        _senderCiphertexts[messageId][chunkIndex] = senderCiphertext;
        _recipientCiphertexts[messageId][chunkIndex] = recipientCiphertext;
    }

    function _messageCiphertextForViewer(
        uint256 messageId,
        MessageRecord storage record,
        address viewer,
        uint256 chunkIndex
    ) internal view returns (ctString memory ciphertext) {
        _requireChunkIndex(record, chunkIndex);

        if (viewer == record.from) {
            return _senderCiphertexts[messageId][chunkIndex];
        }

        if (viewer == record.to) {
            return _recipientCiphertexts[messageId][chunkIndex];
        }

        revert UnauthorizedViewer();
    }

    function _validateEncryptedChunk(itString calldata encryptedChunk) internal pure returns (uint256 cells) {
        cells = encryptedChunk.ciphertext.value.length;
        if (
            cells == 0 ||
            cells != encryptedChunk.signature.length ||
            cells > MAX_CHUNK_CELLS
        ) {
            revert ChunkTooLarge();
        }
    }

    function _slice(
        uint256[] storage source,
        uint256 offset,
        uint256 limit
    ) internal view returns (uint256[] memory page) {
        if (offset >= source.length || limit == 0) {
            return new uint256[](0);
        }

        uint256 end = offset + limit;
        if (end > source.length) {
            end = source.length;
        }

        page = new uint256[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = source[i];
        }
    }

    function _requireMessage(uint256 messageId) internal view returns (MessageRecord storage record) {
        record = _messages[messageId];
        if (!record.exists) {
            revert MessageNotFound();
        }
    }

    function _requireChunkIndex(MessageRecord storage record, uint256 chunkIndex) internal view {
        if (chunkIndex >= record.chunkCount) {
            revert ChunkOutOfBounds();
        }
    }
}
