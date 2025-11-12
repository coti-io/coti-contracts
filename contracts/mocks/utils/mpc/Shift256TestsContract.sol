// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Shift256TestsContract {
    uint256 shlResult;
    uint256 shrResult;

    function getShlResult() public view returns (uint256) {
        return shlResult;
    }

    function getShrResult() public view returns (uint256) {
        return shrResult;
    }

    function shlTest(uint256 a, uint8 shift) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        
        uint256 result = MpcCore.decrypt(MpcCore.shl(a256, shift));
        shlResult = result;
        
        return result;
    }

    function shrTest(uint256 a, uint8 shift) public returns (uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        
        uint256 result = MpcCore.decrypt(MpcCore.shr(a256, shift));
        shrResult = result;
        
        return result;
    }
}

