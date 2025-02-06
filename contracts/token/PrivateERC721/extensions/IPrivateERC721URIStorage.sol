// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @dev ERC-721 token with storage based token URI management.
 */
interface IPrivateERC721URIStorage {
    /**
     * @dev Returns the encrypted Uniform Resource Identifier (URI) for `tokenId` token.
     */
    function tokenURI(uint256 tokenId) external view returns (ctString memory);
}