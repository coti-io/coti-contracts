// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Comparison128TestsContract {
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

    function eqTest(uint128 a, uint128 b) public returns (bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        bool result = MpcCore.decrypt(MpcCore.eq(a128, b128));
        eqResult = result;
        
        return result;
    }

    function neTest(uint128 a, uint128 b) public returns (bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        bool result = MpcCore.decrypt(MpcCore.ne(a128, b128));
        neResult = result;
        
        return result;
    }

    function geTest(uint128 a, uint128 b) public returns (bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        bool result = MpcCore.decrypt(MpcCore.ge(a128, b128));
        geResult = result;
        
        return result;
    }

    function gtTest(uint128 a, uint128 b) public returns (bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        bool result = MpcCore.decrypt(MpcCore.gt(a128, b128));
        gtResult = result;
        
        return result;
    }

    function leTest(uint128 a, uint128 b) public returns (bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        bool result = MpcCore.decrypt(MpcCore.le(a128, b128));
        leResult = result;
        
        return result;
    }

    function ltTest(uint128 a, uint128 b) public returns (bool) {
        gtUint128 a128 = MpcCore.setPublic128(a);
        gtUint128 b128 = MpcCore.setPublic128(b);
        
        bool result = MpcCore.decrypt(MpcCore.lt(a128, b128));
        ltResult = result;
        
        return result;
    }
}

