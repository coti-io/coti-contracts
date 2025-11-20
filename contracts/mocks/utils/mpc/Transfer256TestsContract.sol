// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Transfer256TestsContract {
    uint256 newA;
    uint256 newB;
    bool result;

    function getResults() public view returns (uint256, uint256, bool) {
        return (newA, newB, result);
    }

    function transferTest(uint256 a, uint256 b, uint256 amount) public returns (uint256, uint256, bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        gtUint256 amount256 = MpcCore.setPublic256(amount);
        
        (gtUint256 newA256, gtUint256 newB256, gtBool res) = MpcCore.transfer(a256, b256, amount256);
        
        newA = MpcCore.decrypt(newA256);
        newB = MpcCore.decrypt(newB256);
        result = MpcCore.decrypt(res);
        
        return (newA, newB, result);
    }
}

