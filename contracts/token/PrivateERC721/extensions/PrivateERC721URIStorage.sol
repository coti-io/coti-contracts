// SPDX-License-Identifier: MIT
// COTI Contracts (last updated v0.1.0) (token/PrivateERC721/extensions/PrivateERC721URIStorage.sol)

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

    mapping(uint256 tokenId => utUint64[]) private _tokenURIs;

    /**
     * @dev See {IERC165-supportsInterface}
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(PrivateERC721, IERC165) returns (bool) {
        return interfaceId == ERC4906_INTERFACE_ID || super.supportsInterface(interfaceId);
    }

    function tokenURI(uint256 tokenId) public view virtual returns (ctUint64[] memory) {
        utUint64[] memory _tokenURI = _tokenURIs[tokenId];

        ctUint64[] memory _userTokenURI = new ctUint64[](_tokenURIs[tokenId].length);

        for (uint256 i = 0; i < _tokenURI.length; ++i) {
            _userTokenURI[i] = _tokenURI[i].userCiphertext;
        }
        
        return _userTokenURI;
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        ctUint64[] calldata itTokenURI,
        bytes[] calldata itSignature
    ) internal virtual {
        gtUint64[] memory gtTokenURI = new gtUint64[](itTokenURI.length);

        itUint64 memory it;

        for (uint256 i = 0; i < itTokenURI.length; ++i) {
            it.ciphertext = itTokenURI[i];
            it.signature = itSignature[i];

            gtTokenURI[i] = MpcCore.validateCiphertext(it);
        }

        _setTokenURI(to, tokenId, gtTokenURI, true);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtUint64[] memory gtTokenURI,
        bool updateCiphertext
    ) private {
        if (ownerOf(tokenId) == address(0)) {
            revert ERC721URIStorageNonMintedToken(tokenId);
        }

        // we must first make sure that tokenURI has the correct length
        utUint64[] storage tokenURI_ = _tokenURIs[tokenId];

        utUint64 memory offBoardCombined;

        if (updateCiphertext) {
            for (uint256 i = 0; i < gtTokenURI.length; ++i) {
                offBoardCombined = MpcCore.offBoardCombined(gtTokenURI[i], to);

                tokenURI_.push(offBoardCombined);
            }

            _tokenURIs[tokenId] = tokenURI_;
        } else {
            for (uint256 i = 0; i < gtTokenURI.length; ++i) {
                offBoardCombined = MpcCore.offBoardCombined(gtTokenURI[i], to);

                tokenURI_[i].userCiphertext = offBoardCombined.userCiphertext;
            }

            _tokenURIs[tokenId] = tokenURI_;
        }
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        utUint64[] memory tokenURI_ = _tokenURIs[tokenId];

        gtUint64[] memory gtTokenURI = new gtUint64[](tokenURI_.length);

        for (uint256 i = 0; i < gtTokenURI.length; ++i) {
            gtTokenURI[i] = MpcCore.onBoard(tokenURI_[i].ciphertext);
        }

        address previousOwner = PrivateERC721._update(to, tokenId, auth);

        // reencrypt with the new user key
        _setTokenURI(to, tokenId, gtTokenURI, false);

        return previousOwner;
    }
}