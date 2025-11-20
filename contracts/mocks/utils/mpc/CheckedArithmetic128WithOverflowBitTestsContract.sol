// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract CheckedArithmetic128WithOverflowBitTestsContract {
    uint128 addResult;
    uint128 subResult;
    uint128 mulResult;

    function getAddResult() public view returns (uint128) {
        return addResult;
    }

    function getSubResult() public view returns (uint128) {
        return subResult;
    }

    function getMulResult() public view returns (uint128) {
        return mulResult;
    }

    function checkedAddWithOverflowBitTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        (, gtUint128 gtResult) = MpcCore.checkedAddWithOverflowBit(a128, b128);
        uint128 result = uint128(MpcCore.decrypt(gtResult));
        addResult = result;
        
        return result;
    }

    function checkedSubWithOverflowBitTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        (, gtUint128 gtResult) = MpcCore.checkedSubWithOverflowBit(a128, b128);
        uint128 result = uint128(MpcCore.decrypt(gtResult));
        subResult = result;
        
        return result;
    }

    function checkedMulWithOverflowBitTest(uint128 a, uint128 b) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        (, gtUint128 gtResult) = MpcCore.checkedMulWithOverflowBit(a128, b128);
        uint128 result = uint128(MpcCore.decrypt(gtResult));
        mulResult = result;
        
        return result;
    }
}

