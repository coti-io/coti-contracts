// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Arithmetic256TestsContract {
    uint256 addResult;
    uint256 subResult;
    uint256 mulResult;
    uint256 divResult;
    uint256 remResult;

    function getAddResult() public view returns (uint256) {
        return addResult;
    }

    function getSubResult() public view returns (uint256) {
        return subResult;
    }

    function getMulResult() public view returns (uint256) {
        return mulResult;
    }

    function getDivResult() public view returns (uint256) {
        return divResult;
    }

    function getRemResult() public view returns (uint256) {
        return remResult;
    }

    function addTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.add(a256, b256));
        addResult = result;
        
        // Verify with scalar operations
        require(result == MpcCore.decrypt(MpcCore.add(a, b256)), "addTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.add(a256, b)), "addTest: scalar failed");
        
        return result;
    }

    function checkedAddTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.checkedAdd(a256, b256));
        addResult = result;
        
        return result;
    }

    function subTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.sub(a256, b256));
        subResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.sub(a, b256)), "subTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.sub(a256, b)), "subTest: scalar failed");
        
        return result;
    }

    function checkedSubTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.checkedSub(a256, b256));
        subResult = result;
        
        return result;
    }

    function mulTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.mul(a256, b256));
        mulResult = result;
        
        require(result == MpcCore.decrypt(MpcCore.mul(a, b256)), "mulTest: scalar failed");
        require(result == MpcCore.decrypt(MpcCore.mul(a256, b)), "mulTest: scalar failed");
        
        return result;
    }

    function checkedMulTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.checkedMul(a256, b256));
        mulResult = result;
        
        return result;
    }

    function divTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.div(a256, b256));
        divResult = result;
        
        return result;
    }

    function remTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.rem(a256, b256));
        remResult = result;
        
        return result;
    }
}