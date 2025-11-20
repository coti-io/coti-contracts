// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Bitwise128TestsContract {
    uint128 andResult;
    uint128 orResult;
    uint128 xorResult;

    function getAndResult() public view returns (uint128) {
        return andResult;
    }

    function getOrResult() public view returns (uint128) {
        return orResult;
    }

    function getXorResult() public view returns (uint128) {
        return xorResult;
    }

    function andTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.and(a128, b128)));
        andResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.and(a, b128))), "andTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.and(a128, b))), "andTest: scalar failed");
        
        return result;
    }

    function orTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.or(a128, b128)));
        orResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.or(a, b128))), "orTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.or(a128, b))), "orTest: scalar failed");
        
        return result;
    }

    function xorTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.xor(a128, b128)));
        xorResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.xor(a, b128))), "xorTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.xor(a128, b))), "xorTest: scalar failed");
        
        return result;
    }
}

