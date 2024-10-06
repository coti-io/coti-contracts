// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {PrivateERC721} from "../../../token/PrivateERC721/PrivateERC721.sol";
import {PrivateERC721URIStorage} from "../../../token/PrivateERC721/extensions/PrivateERC721URIStorage.sol";
import "../../../utils/mpc/MpcCore.sol";

contract PrivateERC721URIStorageMock is PrivateERC721URIStorage {
    uint256 private _totalSupply;

    event Minted(address indexed to, uint256 indexed tokenId);

    constructor() PrivateERC721("Example", "EXL") {}

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function mint(
        address to,
        itString calldata itTokenURI
    ) public {
        uint256 tokenId = _totalSupply;
        
        _mint(to, tokenId);

        PrivateERC721URIStorage._setTokenURI(msg.sender, tokenId, itTokenURI);

        _totalSupply += 1;

        emit Minted(to, tokenId);
    }
}