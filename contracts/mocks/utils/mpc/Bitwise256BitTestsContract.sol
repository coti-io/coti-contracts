// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Bitwise256BitTestsContract {

    uint256[] public numbers2;

    function andTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.and(gtA, gtB));

            assert(numbers2[i] == MpcCore.decrypt(MpcCore.and(a[i], gtB)));
            assert(numbers2[i] == MpcCore.decrypt(MpcCore.and(gtA, b[i])));
        }
    }

    function orTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.or(gtA, gtB));

            assert(numbers2[i] == MpcCore.decrypt(MpcCore.or(a[i], gtB)));
            assert(numbers2[i] == MpcCore.decrypt(MpcCore.or(gtA, b[i])));
        }
    }

    function xorTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.xor(gtA, gtB));

            assert(numbers2[i] == MpcCore.decrypt(MpcCore.xor(a[i], gtB)));
            assert(numbers2[i] == MpcCore.decrypt(MpcCore.xor(gtA, b[i])));
        }
    }

    function shlTest(uint256[] calldata a, uint8[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.shl(gtA, b[i]));
        }
    }

    function shrTest(uint256[] calldata a, uint8[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.shr(gtA, b[i]));
        }
    }

    function _resetNumbers2(uint256 length) internal {
        // Reset the numbers array
        delete numbers2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbers2.push(0);
        }
    }
}