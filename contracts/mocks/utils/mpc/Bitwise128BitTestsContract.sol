// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Bitwise128BitTestsContract {

    uint128[] public numbers;

    function andTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.and(gtA, gtB));

            assert(numbers[i] == MpcCore.decrypt(MpcCore.and(a[i], gtB)));
            assert(numbers[i] == MpcCore.decrypt(MpcCore.and(gtA, b[i])));
        }
    }

    function orTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.or(gtA, gtB));

            assert(numbers[i] == MpcCore.decrypt(MpcCore.or(a[i], gtB)));
            assert(numbers[i] == MpcCore.decrypt(MpcCore.or(gtA, b[i])));
        }
    }

    function xorTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.xor(gtA, gtB));

            assert(numbers[i] == MpcCore.decrypt(MpcCore.xor(a[i], gtB)));
            assert(numbers[i] == MpcCore.decrypt(MpcCore.xor(gtA, b[i])));
        }
    }

    function shlTest(uint128[] calldata a, uint8[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.shl(gtA, b[i]));
        }
    }

    function shrTest(uint128[] calldata a, uint8[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.shr(gtA, b[i]));
        }
    }

    function _resetNumbers(uint256 length) internal {
        // Reset the numbers array
        delete numbers;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbers.push(0);
        }
    }
}