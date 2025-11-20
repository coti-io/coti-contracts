// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Shift128TestsContract {
    uint128 shlResult;
    uint128 shrResult;

    function getShlResult() public view returns (uint128) {
        return shlResult;
    }

    function getShrResult() public view returns (uint128) {
        return shrResult;
    }

    function shlTest(uint128 a, uint8 shift) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.shl(a128, shift)));
        shlResult = result;
        
        return result;
    }

    function shrTest(uint128 a, uint8 shift) public returns (uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.shr(a128, shift)));
        shrResult = result;
        
        return result;
    }
}

