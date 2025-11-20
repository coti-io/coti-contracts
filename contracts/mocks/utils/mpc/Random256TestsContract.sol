// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Random256TestsContract {
    uint256 randomResult;
    uint256 randomBoundedResult;

    function getRandom() public view returns (uint256) {
        return randomResult;
    }

    function getRandomBounded() public view returns (uint256) {
        return randomBoundedResult;
    }

    function randomTest() public returns (uint256) {
        uint256 result = MpcCore.decrypt(MpcCore.rand256());
        randomResult = result;
        
        return result;
    }

    function randomBoundedTest(uint8 numBits) public returns (uint256) {
        uint256 result = MpcCore.decrypt(MpcCore.randBoundedBits256(numBits));
        randomBoundedResult = result;
        
        return result;
    }
}

