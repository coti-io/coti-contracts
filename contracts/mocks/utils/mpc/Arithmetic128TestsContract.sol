// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Arithmetic128TestsContract {
    uint128 addResult;
    uint128 subResult;
    uint128 mulResult;
    uint128 divResult;
    uint128 remResult;

    function getAddResult() public view returns (uint128) {
        return addResult;
    }

    function getSubResult() public view returns (uint128) {
        return subResult;
    }

    function getMulResult() public view returns (uint128) {
        return mulResult;
    }

    function getDivResult() public view returns (uint128) {
        return divResult;
    }

    function getRemResult() public view returns (uint128) {
        return remResult;
    }

    function addTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.add(a128, b128)));
        addResult = result;
        
        // Verify with scalar operations
        require(result == uint128(MpcCore.decrypt(MpcCore.add(a, b128))), "addTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.add(a128, b))), "addTest: scalar failed");
        
        return result;
    }

    function checkedAddTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.checkedAdd(a128, b128)));
        addResult = result;
        
        return result;
    }

    function subTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.sub(a128, b128)));
        subResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.sub(a, b128))), "subTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.sub(a128, b))), "subTest: scalar failed");
        
        return result;
    }

    function checkedSubTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.checkedSub(a128, b128)));
        subResult = result;
        
        return result;
    }

    function mulTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.mul(a128, b128)));
        mulResult = result;
        
        require(result == uint128(MpcCore.decrypt(MpcCore.mul(a, b128))), "mulTest: scalar failed");
        require(result == uint128(MpcCore.decrypt(MpcCore.mul(a128, b))), "mulTest: scalar failed");
        
        return result;
    }

    function checkedMulTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.checkedMul(a128, b128)));
        mulResult = result;
        
        return result;
    }

    function divTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.div(a128, b128)));
        divResult = result;
        
        return result;
    }

    function remTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.rem(a128, b128)));
        remResult = result;
        
        return result;
    }
}

