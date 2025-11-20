// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract TransferWithAllowance128TestsContract {
    uint128 newA;
    uint128 newB;
    bool result;
    uint128 newAllowance;

    function getResults() public view returns (uint128, uint128, bool, uint128) {
        return (newA, newB, result, newAllowance);
    }

    function transferWithAllowanceTest(uint128 a, uint128 b, uint128 amount, uint128 allowance) public returns (uint128, uint128, bool, uint128) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        gtUint128 amount128 = MpcCore.setPublic128(amount);
        gtUint128 allowance128 = MpcCore.setPublic128(allowance);
        
        (gtUint128 newA128, gtUint128 newB128, gtBool res, gtUint128 newAllowance128) = MpcCore.transferWithAllowance(a128, b128, amount128, allowance128);
        
        newA = uint128(MpcCore.decrypt(newA128));
        newB = uint128(MpcCore.decrypt(newB128));
        result = MpcCore.decrypt(res);
        newAllowance = uint128(MpcCore.decrypt(newAllowance128));
        
        return (newA, newB, result, newAllowance);
    }
}

