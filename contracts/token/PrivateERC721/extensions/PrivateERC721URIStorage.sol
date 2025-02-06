// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {PrivateERC721} from "../PrivateERC721.sol";
import {IERC4906} from "@openzeppelin/contracts/interfaces/IERC4906.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import "../../../utils/mpc/MpcCore.sol";

/**
 * @dev ERC721 token with storage-based encrypted token URI management.
 */
abstract contract PrivateERC721URIStorage is IERC4906, PrivateERC721 {

    error ERC721URIStorageNonMintedToken(uint256 tokenId);

    // Interface ID as defined in ERC-4906. This does not correspond to a traditional interface ID as ERC-4906 only
    // defines events and does not include any external function.
    bytes4 private constant ERC4906_INTERFACE_ID = bytes4(0x000000); // TODO: GET INTERFACE ID

    mapping(uint256 tokenId => utString) private _tokenURIs;

    /**
     * @dev See {IERC165-supportsInterface}
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(PrivateERC721, IERC165) returns (bool) {
        return interfaceId == ERC4906_INTERFACE_ID || super.supportsInterface(interfaceId);
    }

    function tokenURI(uint256 tokenId) public view virtual returns (ctString memory) {
        return _tokenURIs[tokenId].userCiphertext;
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        itString calldata itTokenURI
    ) internal virtual {
        gtString memory gtTokenURI = MpcCore.validateCiphertext(itTokenURI);

        _setTokenURI(to, tokenId, gtTokenURI, true);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        ctString memory ctTokenURI
    ) internal virtual {
        gtString memory gtTokenURI = MpcCore.onBoard(ctTokenURI);

        _setTokenURI(to, tokenId, gtTokenURI, true);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtString memory gtTokenURI
    ) internal virtual {
        _setTokenURI(to, tokenId, gtTokenURI, true);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtString memory gtTokenURI,
        bool updateCiphertext
    ) private {
        if (ownerOf(tokenId) == address(0)) {
            revert ERC721URIStorageNonMintedToken(tokenId);
        }

        utString memory utTokenURI = MpcCore.offBoardCombined(gtTokenURI, to);

        if (updateCiphertext) {
            _tokenURIs[tokenId] = utTokenURI;
        } else {
             _tokenURIs[tokenId].userCiphertext = utTokenURI.userCiphertext;
        }
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        gtString memory gtTokenURI = MpcCore.onBoard(_tokenURIs[tokenId].ciphertext);

        address previousOwner = PrivateERC721._update(to, tokenId, auth);

        // reencrypt with the new user key
        _setTokenURI(to, tokenId, gtTokenURI, false);

        return previousOwner;
    }
}