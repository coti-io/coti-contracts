// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SoulboundNodeNFT
 * @notice ERC-721 Soulbound Node Identity NFT with ERC-5192 support
 *
 * @dev High-level properties:
 *  - Non-transferable (Soulbound)
 *  - ERC-5192 compliant (locked NFTs)
 *  - Only contract owner can mint
 *  - One NFT per wallet enforced
 *  - Minting can be paused by owner
 *  - Unlimited total supply
 *  - Burnable by token owner or contract owner
 *  - On-chain base64-encoded JSON metadata
 *  - Uses custom Solidity errors (gas efficient)
 *
 * @dev Intended use case:
 *  - Node / validator identity
 *  - Credentials
 *  - Non-transferable attestations
 */

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

/// -----------------------------------------------------------------------
/// ERC-5192: Minimal Soulbound NFTs
/// -----------------------------------------------------------------------

/**
 * @dev ERC-5192 interface for signaling soulbound (non-transferable) NFTs.
 * See: https://eips.ethereum.org/EIPS/eip-5192
 */
interface IERC5192 {
    /// @notice Emitted when a token is locked (becomes soulbound)
    event Locked(uint256 tokenId);

    /// @notice Returns whether a token is locked (non-transferable)
    function locked(uint256 tokenId) external view returns (bool);
}

/// -----------------------------------------------------------------------
/// Custom errors (cheaper than revert strings)
/// -----------------------------------------------------------------------

error InvalidRecipient();
error AlreadyOwnsNodeNFT();
error NodeNameRequired();
error NodeNameTooLong();
error SocialURLTooLong();
error NonexistentToken();
error SoulboundOperation();
error NotAuthorized();
error MintPaused();

/// -----------------------------------------------------------------------
/// Main contract
/// -----------------------------------------------------------------------

contract SoulboundNodeNFT is ERC721, Ownable, IERC5192 {
    using Strings for uint256;

    /// @notice Last minted token ID (starts at 0, first mint = 1)
    uint256 public nextTokenId;

    /// @notice Maximum length (in bytes) for nodeName and socialURL
    uint256 public constant MAX_TEXT_BYTES = 150;

    /**
     * @notice If true, minting is paused.
     * @dev Burn operations are NOT affected.
     */
    bool public mintPaused;

    /// @notice Node-specific metadata stored on-chain
    struct NodeData {
        string nodeName;        // required
        string nodeImageURI;    // optional (ipfs:// or https://)
        string socialURL;       // optional
    }

    /// @dev tokenId => NodeData
    mapping(uint256 => NodeData) private _nodeData;

    /// @notice Emitted when a new node NFT is minted
    event NodeMinted(
        address indexed to,
        uint256 indexed tokenId,
        string nodeName,
        string nodeImageURI,
        string socialURL
    );

    /// @notice Emitted when mint pause state is changed
    event MintPausedSet(bool paused);

    /**
     * @notice Contract constructor
     * @param name_ ERC-721 collection name
     * @param symbol_ ERC-721 collection symbol
     * @param initialOwner Address that becomes contract owner
     */
    constructor(
        string memory name_,
        string memory symbol_,
        address initialOwner
    ) ERC721(name_, symbol_) {
        _transferOwnership(initialOwner);
        mintPaused = false;
    }

    /// -----------------------------------------------------------------------
    /// Admin: pause / unpause minting
    /// -----------------------------------------------------------------------

    /**
     * @notice Pause minting operations
     * @dev Only the contract owner can call this function
     * @dev Only affects minting, not burning operations
     * @dev Emits MintPausedSet event with true
     */
    function pauseMint() external onlyOwner {
        mintPaused = true;
        emit MintPausedSet(true);
    }

    /**
     * @notice Unpause minting operations
     * @dev Only the contract owner can call this function
     * @dev Emits MintPausedSet event with false
     */
    function unpauseMint() external onlyOwner {
        mintPaused = false;
        emit MintPausedSet(false);
    }

    /// -----------------------------------------------------------------------
    /// ERC-5192 (Soulbound signaling)
    /// -----------------------------------------------------------------------

    /**
     * @notice Check whether a token is locked (soulbound)
     * @param tokenId Token ID to check
     * @return Always true for existing tokens
     * @dev Reverts if token does not exist
     */
    function locked(uint256 tokenId) external view override returns (bool) {
        if (_ownerOf(tokenId) == address(0)) revert NonexistentToken();
        return true;
    }

    /**
     * @notice ERC-165 interface support
     * @param interfaceId Interface identifier to check
     * @return true if the contract supports the interface, false otherwise
     * @dev Supports ERC721, ERC165, and ERC5192 interfaces
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721)
        returns (bool)
    {
        return
            interfaceId == type(IERC5192).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /// -----------------------------------------------------------------------
    /// Minting (ONLY OWNER)
    /// -----------------------------------------------------------------------

    /**
     * @notice Mint a new soulbound Node NFT
     * @param to Recipient address
     * @param nodeName Node name (required, <=150 bytes)
     * @param nodeImageURI Optional image URI
     * @param socialURL Optional social URL (<=150 bytes)
     * @return tokenId The ID of the newly minted token
     * @dev Restrictions:
     *  - Only contract owner can mint
     *  - Minting must not be paused
     *  - Recipient may own at most one NFT
     * @dev Reverts if:
     *  - Minting is paused (MintPaused)
     *  - to is the zero address (InvalidRecipient)
     *  - to already owns an NFT (AlreadyOwnsNodeNFT)
     *  - nodeName is empty (NodeNameRequired)
     *  - nodeName exceeds MAX_TEXT_BYTES (NodeNameTooLong)
     *  - socialURL exceeds MAX_TEXT_BYTES (SocialURLTooLong)
     * @dev Emits Locked and NodeMinted events
     */
    function mintNode(
        address to,
        string calldata nodeName,
        string calldata nodeImageURI,
        string calldata socialURL
    ) external onlyOwner returns (uint256 tokenId) {
        if (mintPaused) revert MintPaused();
        if (to == address(0)) revert InvalidRecipient();
        if (balanceOf(to) != 0) revert AlreadyOwnsNodeNFT();
        if (bytes(nodeName).length == 0) revert NodeNameRequired();
        if (bytes(nodeName).length > MAX_TEXT_BYTES) revert NodeNameTooLong();
        if (bytes(socialURL).length > MAX_TEXT_BYTES) revert SocialURLTooLong();

        tokenId = ++nextTokenId;

        _safeMint(to, tokenId);

        _nodeData[tokenId] = NodeData({
            nodeName: nodeName,
            nodeImageURI: nodeImageURI,
            socialURL: socialURL
        });

        emit Locked(tokenId);
        emit NodeMinted(to, tokenId, nodeName, nodeImageURI, socialURL);
    }

    /**
     * @notice Get node metadata for a token
     * @param tokenId Token ID to query
     * @return NodeData struct containing nodeName, nodeImageURI, and socialURL
     * @dev Reverts if the token does not exist (NonexistentToken)
     */
    function nodeData(uint256 tokenId) external view returns (NodeData memory) {
        if (_ownerOf(tokenId) == address(0)) revert NonexistentToken();
        return _nodeData[tokenId];
    }

    /// -----------------------------------------------------------------------
    /// Soulbound restrictions (disable transfers & approvals)
    /// -----------------------------------------------------------------------

    /**
     * @notice Approve an address to transfer a token (disabled for soulbound NFTs)
     * @dev Always reverts with SoulboundOperation error since tokens cannot be transferred
     * @dev Parameters match ERC721 interface but are unused
     */
    function approve(address /* operator */, uint256 /* tokenId */) public pure override {
        revert SoulboundOperation();
    }

    /**
     * @notice Approve an operator for all tokens (disabled for soulbound NFTs)
     * @dev Always reverts with SoulboundOperation error since tokens cannot be transferred
     * @dev Parameters match ERC721 interface but are unused
     */
    function setApprovalForAll(address /* operator */, bool /* approved */) public pure override {
        revert SoulboundOperation();
    }

    /**
     * @notice Transfer a token (disabled for soulbound NFTs)
     * @dev Always reverts with SoulboundOperation error since tokens are soulbound
     * @dev Parameters match ERC721 interface but are unused
     */
    function transferFrom(address /* from */, address /* to */, uint256 /* tokenId */) public pure override {
        revert SoulboundOperation();
    }

    /**
     * @notice Safely transfer a token (disabled for soulbound NFTs)
     * @dev Always reverts with SoulboundOperation error since tokens are soulbound
     * @dev Parameters match ERC721 interface but are unused
     */
    function safeTransferFrom(address /* from */, address /* to */, uint256 /* tokenId */) public pure override {
        revert SoulboundOperation();
    }

    /**
     * @notice Safely transfer a token with data (disabled for soulbound NFTs)
     * @dev Always reverts with SoulboundOperation error since tokens are soulbound
     * @dev Parameters match ERC721 interface but are unused
     */
    function safeTransferFrom(address /* from */, address /* to */, uint256 /* tokenId */, bytes memory /* data */) public pure override {
        revert SoulboundOperation();
    }

    /// -----------------------------------------------------------------------
    /// Burning
    /// -----------------------------------------------------------------------

    /**
     * @notice Burn a token, permanently removing it from circulation
     * @param tokenId Token ID to burn
     * @dev Callable by token owner or contract owner
     * @dev Reverts if:
     *  - Caller is not the token owner and not the contract owner (NotAuthorized)
     *  - Token does not exist
     * @dev Deletes the associated node data after burning
     */
    function burn(uint256 tokenId) external {
        address tokenOwner = ownerOf(tokenId);
        if (msg.sender != tokenOwner && msg.sender != owner()) revert NotAuthorized();

        _burn(tokenId);
        delete _nodeData[tokenId];
    }

    /// -----------------------------------------------------------------------
    /// Metadata (on-chain JSON)
    /// -----------------------------------------------------------------------

    /**
     * @notice Return token metadata as base64-encoded JSON
     * @param tokenId Token ID to query
     * @return A base64-encoded JSON data URI containing the token metadata
     * @dev Returns on-chain JSON metadata as a data URI (data:application/json;base64,...)
     * @dev Includes token name, description, attributes (node name, social URL), and optional image
     * @dev Reverts if the token does not exist (NonexistentToken)
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        if (_ownerOf(tokenId) == address(0)) revert NonexistentToken();

        NodeData memory d = _nodeData[tokenId];

        string memory attributes = string.concat(
            '[{"trait_type":"Node name","value":"', _escapeJSON(d.nodeName), '"}',
            ',{"trait_type":"Social URL","value":"', _escapeJSON(d.socialURL), '"}]'
        );

        string memory imagePart = bytes(d.nodeImageURI).length == 0
            ? ""
            : string.concat(',"image":"', _escapeJSON(d.nodeImageURI), '"');

        string memory json = string.concat(
            '{"name":"Node #', tokenId.toString(),
            '","description":"Soulbound Node NFT",',
            '"attributes":', attributes,
            imagePart,
            "}"
        );

        return string.concat(
            "data:application/json;base64,",
            Base64.encode(bytes(json))
        );
    }

    /// -----------------------------------------------------------------------
    /// Internal helpers
    /// -----------------------------------------------------------------------

    /**
     * @notice Escape special JSON characters in a string
     * @param s The string to escape
     * @return The escaped string with backslashes added before quotes and backslashes
     * @dev Used internally to safely embed strings in JSON metadata
     * @dev Escapes double quotes (") and backslashes (\) by prefixing them with a backslash
     */
    function _escapeJSON(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        bytes memory out = new bytes(b.length * 2);
        uint256 j;

        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            if (c == bytes1('"') || c == bytes1("\\")) {
                out[j++] = bytes1("\\");
                out[j++] = c;
            } else {
                out[j++] = c;
            }
        }

        bytes memory trimmed = new bytes(j);
        for (uint256 k = 0; k < j; k++) trimmed[k] = out[k];
        return string(trimmed);
    }
}
