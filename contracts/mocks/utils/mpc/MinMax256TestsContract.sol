// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract MinMax256TestsContract {
    uint256 minResult;
    uint256 maxResult;

    function getMinResult() public view returns (uint256) {
        return minResult;
    }

    function getMaxResult() public view returns (uint256) {
        return maxResult;
    }

    function minTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.min(a256, b256));
        minResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.min(a, b256)), "minTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.min(a256, b)), "minTest: scalar failed");
        
        return result;
    }

    function maxTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.max(a256, b256));
        maxResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.max(a, b256)), "maxTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.max(a256, b)), "maxTest: scalar failed");
        
        return result;
    }
}

