// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Mux256TestsContract {
    uint256 muxResult;

    function getMuxResult() public view returns (uint256) {
        return muxResult;
    }

    function muxTest(bool bit, uint256 a, uint256 b) public returns (uint256) {
        gtBool bitBool = MpcCore.setPublic(bit);
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        uint256 result = MpcCore.decrypt(MpcCore.mux(bitBool, a256, b256));
        muxResult = result;
        
        return result;
    }
}

