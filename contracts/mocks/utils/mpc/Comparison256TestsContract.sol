// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Comparison256TestsContract {
    bool eqResult;
    bool neResult;
    bool geResult;
    bool gtResult;
    bool leResult;
    bool ltResult;

    function getEqResult() public view returns (bool) {
        return eqResult;
    }

    function getNeResult() public view returns (bool) {
        return neResult;
    }

    function getGeResult() public view returns (bool) {
        return geResult;
    }

    function getGtResult() public view returns (bool) {
        return gtResult;
    }

    function getLeResult() public view returns (bool) {
        return leResult;
    }

    function getLtResult() public view returns (bool) {
        return ltResult;
    }

    function eqTest(uint256 a, uint256 b) public returns (bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        bool result = MpcCore.decrypt(MpcCore.eq(a256, b256));
        eqResult = result;
        
        return result;
    }

    function neTest(uint256 a, uint256 b) public returns (bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        bool result = MpcCore.decrypt(MpcCore.ne(a256, b256));
        neResult = result;
        
        return result;
    }

    function geTest(uint256 a, uint256 b) public returns (bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        bool result = MpcCore.decrypt(MpcCore.ge(a256, b256));
        geResult = result;
        
        return result;
    }

    function gtTest(uint256 a, uint256 b) public returns (bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        bool result = MpcCore.decrypt(MpcCore.gt(a256, b256));
        gtResult = result;
        
        return result;
    }

    function leTest(uint256 a, uint256 b) public returns (bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        bool result = MpcCore.decrypt(MpcCore.le(a256, b256));
        leResult = result;
        
        return result;
    }

    function ltTest(uint256 a, uint256 b) public returns (bool) {
        gtUint256 a256 = MpcCore.setPublic256(a);
        gtUint256 b256 = MpcCore.setPublic256(b);
        
        bool result = MpcCore.decrypt(MpcCore.lt(a256, b256));
        ltResult = result;
        
        return result;
    }
}

