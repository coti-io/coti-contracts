// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract MinMax128TestsContract {
    uint128 minResult;
    uint128 maxResult;

    function getMinResult() public view returns (uint128) {
        return minResult;
    }

    function getMaxResult() public view returns (uint128) {
        return maxResult;
    }

    function minTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.min(a128, b128)));
        minResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.min(a, b128))), "minTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.min(a128, b))), "minTest: scalar failed");
        
        return result;
    }

    function maxTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.max(a128, b128)));
        maxResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.max(a, b128))), "maxTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.max(a128, b))), "maxTest: scalar failed");
        
        return result;
    }
}

