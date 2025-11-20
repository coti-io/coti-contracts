// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Mux128TestsContract {
    uint128 muxResult;

    function getMuxResult() public view returns (uint128) {
        return muxResult;
    }

    function muxTest(bool bit, uint128 a, uint128 b) public returns (uint128) {
        gtBool bitBool = MpcCore.setPublic(bit);
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        uint128 result = uint128(MpcCore.decrypt(MpcCore.mux(bitBool, a128, b128)));
        muxResult = result;
        
        return result;
    }
}

