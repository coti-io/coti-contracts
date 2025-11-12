// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Random128TestsContract {
    uint128 randomResult;
    uint128 randomBoundedResult;

    function getRandom() public view returns (uint128) {
        return randomResult;
    }

    function getRandomBounded() public view returns (uint128) {
        return randomBoundedResult;
    }

    function randomTest() public returns (uint128) {
        uint128 result = uint128(MpcCore.decrypt(MpcCore.rand128()));
        randomResult = result;
        
        return result;
    }

    function randomBoundedTest(uint8 numBits) public returns (uint128) {
        uint128 result = uint128(MpcCore.decrypt(MpcCore.randBoundedBits128(numBits)));
        randomBoundedResult = result;
        
        return result;
    }
}

