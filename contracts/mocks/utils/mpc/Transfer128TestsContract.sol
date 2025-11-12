// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Transfer128TestsContract {
    uint128 newA;
    uint128 newB;
    bool result;

    function getResults() public view returns (uint128, uint128, bool) {
        return (newA, newB, result);
    }

    function transferTest(uint128 a, uint128 b, uint128 amount) public returns (uint128, uint128, bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        gtUint128 amount128 = MpcCore.setPublic128(amount);
        
        (gtUint128 newA128, gtUint128 newB128, gtBool res) = MpcCore.transfer(a128, b128, amount128);
        
        newA = uint128(MpcCore.decrypt(newA128));
        newB = uint128(MpcCore.decrypt(newB128));
        result = MpcCore.decrypt(res);
        
        return (newA, newB, result);
    }
}

