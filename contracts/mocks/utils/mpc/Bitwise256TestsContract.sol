// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Bitwise256TestsContract {
    uint256 andResult;
    uint256 orResult;
    uint256 xorResult;

    function getAndResult() public view returns (uint256) {
        return andResult;
    }

    function getOrResult() public view returns (uint256) {
        return orResult;
    }

    function getXorResult() public view returns (uint256) {
        return xorResult;
    }

    function andTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.and(a256, b256));
        andResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.and(a, b256)), "andTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.and(a256, b)), "andTest: scalar failed");
        
        return result;
    }

    function orTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.or(a256, b256));
        orResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.or(a, b256)), "orTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.or(a256, b)), "orTest: scalar failed");
        
        return result;
    }

    function xorTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.xor(a256, b256));
        xorResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.xor(a, b256)), "xorTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.xor(a256, b)), "xorTest: scalar failed");
        
        return result;
    }

    // Note: NOT operation is not supported for 128-bit and 256-bit types in the MPC precompile
    // It only supports NOT for boolean types
}

