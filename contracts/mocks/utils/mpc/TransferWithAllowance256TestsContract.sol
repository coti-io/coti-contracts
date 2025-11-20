// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract TransferWithAllowance256TestsContract {
    uint256 newA;
    uint256 newB;
    bool result;
    uint256 newAllowance;

    function getResults() public view returns (uint256, uint256, bool, uint256) {
        return (newA, newB, result, newAllowance);
    }

    function transferWithAllowanceTest(uint256 a, uint256 b, uint256 amount, uint256 allowance) public returns (uint256, uint256, bool, uint256) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        gtUint256 amount256 = MpcCore.setPublic256(amount);
        gtUint256 allowance256 = MpcCore.setPublic256(allowance);
        
        (gtUint256 newA256, gtUint256 newB256, gtBool res, gtUint256 newAllowance256) = MpcCore.transferWithAllowance(a256, b256, amount256, allowance256);
        
        newA = MpcCore.decrypt(newA256);
        newB = MpcCore.decrypt(newB256);
        result = MpcCore.decrypt(res);
        newAllowance = MpcCore.decrypt(newAllowance256);
        
        return (newA, newB, result, newAllowance);
    }
}

