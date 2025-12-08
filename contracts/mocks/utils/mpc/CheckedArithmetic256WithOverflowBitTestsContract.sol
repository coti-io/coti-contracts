// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract CheckedArithmetic256WithOverflowBitTestsContract {
    uint256 addResult;
    uint256 subResult;
    uint256 mulResult;
    bool overflowBit;

    function getAddResult() public view returns (uint256) {
        return addResult;
    }

    function getSubResult() public view returns (uint256) {
        return subResult;
    }

    function getMulResult() public view returns (uint256) {
        return mulResult;
    }

    function getOverflowBit() public view returns (bool) {
        return overflowBit;
    }

    function checkedAddWithOverflowBitTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        (gtBool overflow, gtUint256 gtResult) = MpcCore.checkedAddWithOverflowBit(a256, b256);
        uint256 result = MpcCore.decrypt(gtResult);
        overflowBit = MpcCore.decrypt(overflow);
        addResult = result;
        
        return result;
    }

    function checkedSubWithOverflowBitTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        (gtBool overflow, gtUint256 gtResult) = MpcCore.checkedSubWithOverflowBit(a256, b256);
        uint256 result = MpcCore.decrypt(gtResult);
        overflowBit = MpcCore.decrypt(overflow);
        subResult = result;
        
        return result;
    }

    function checkedMulWithOverflowBitTest(uint256 a, uint256 b) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        (gtBool overflow, gtUint256 gtResult) = MpcCore.checkedMulWithOverflowBit(a256, b256);
        uint256 result = MpcCore.decrypt(gtResult);
        overflowBit = MpcCore.decrypt(overflow);
        mulResult = result;
        
        return result;
    }
}

