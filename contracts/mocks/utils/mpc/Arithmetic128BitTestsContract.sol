// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Arithmetic128BitTestsContract {

    bool[] public overflows;
    bool[] public overflowsLHS;
    bool[] public overflowsRHS;
    uint128[] public numbers;
    uint128[] public numbersLHS;
    uint128[] public numbersRHS;

    function addTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.add(gtA, gtB));

            assert(numbers[i] == MpcCore.decrypt(MpcCore.add(a[i], gtB)));
            assert(numbers[i] == MpcCore.decrypt(MpcCore.add(gtA, b[i])));
        }
    }

    function checkedAddTest(uint128 a, uint128 b) public {
        _resetNumbers(1);

        gtUint128 memory gtA = MpcCore.setPublic128(a);
        gtUint128 memory gtB = MpcCore.setPublic128(b);

        numbers[0] = MpcCore.decrypt(MpcCore.checkedAdd(gtA, gtB));

        assert(numbers[0] == MpcCore.decrypt(MpcCore.checkedAdd(a, gtB)));
        assert(numbers[0] == MpcCore.decrypt(MpcCore.checkedAdd(gtA, b)));
    }

    function checkedAddWithOverflowBitTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetOverflows(a.length);
        _resetOverflowsLHS(a.length);
        _resetOverflowsRHS(a.length);
        _resetNumbers(a.length);
        _resetNumbersLHS(a.length);
        _resetNumbersRHS(a.length);

        gtBool bit;
        gtBool bitLHS;
        gtBool bitRHS;
        gtUint128 memory result;
        gtUint128 memory resultLHS;
        gtUint128 memory resultRHS;

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            (bit, result) = MpcCore.checkedAddWithOverflowBit(gtA, gtB);
            (bitLHS, resultLHS) = MpcCore.checkedAddWithOverflowBit(a[i], gtB);
            (bitRHS, resultRHS) = MpcCore.checkedAddWithOverflowBit(gtA, b[i]);

            overflows[i] = MpcCore.decrypt(bit);
            overflowsLHS[i] = MpcCore.decrypt(bitLHS);
            overflowsRHS[i] = MpcCore.decrypt(bitRHS);
            numbers[i] = MpcCore.decrypt(result);
            numbersLHS[i] = MpcCore.decrypt(resultLHS);
            numbersRHS[i] = MpcCore.decrypt(resultRHS);
        }
    }

    function subTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.sub(gtA, gtB));

            assert(numbers[i] == MpcCore.decrypt(MpcCore.sub(a[i], gtB)));
            assert(numbers[i] == MpcCore.decrypt(MpcCore.sub(gtA, b[i])));
        }
    }

    function checkedSubTest(uint128 a, uint128 b) public {
        _resetNumbers(1);

        gtUint128 memory gtA = MpcCore.setPublic128(a);
        gtUint128 memory gtB = MpcCore.setPublic128(b);

        numbers[0] = MpcCore.decrypt(MpcCore.checkedSub(gtA, gtB));

        assert(numbers[0] == MpcCore.decrypt(MpcCore.checkedSub(a, gtB)));
        assert(numbers[0] == MpcCore.decrypt(MpcCore.checkedSub(gtA, b)));
    }

    function checkedSubWithOverflowBitTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetOverflows(a.length);
        _resetOverflowsLHS(a.length);
        _resetOverflowsRHS(a.length);
        _resetNumbers(a.length);
        _resetNumbersLHS(a.length);
        _resetNumbersRHS(a.length);

        gtBool bit;
        gtBool bitLHS;
        gtBool bitRHS;
        gtUint128 memory result;
        gtUint128 memory resultLHS;
        gtUint128 memory resultRHS;

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            (bit, result) = MpcCore.checkedSubWithOverflowBit(gtA, gtB);
            (bitLHS, resultLHS) = MpcCore.checkedSubWithOverflowBit(a[i], gtB);
            (bitRHS, resultRHS) = MpcCore.checkedSubWithOverflowBit(gtA, b[i]);

            overflows[i] = MpcCore.decrypt(bit);
            overflowsLHS[i] = MpcCore.decrypt(bitLHS);
            overflowsRHS[i] = MpcCore.decrypt(bitRHS);
            numbers[i] = MpcCore.decrypt(result);
            numbersLHS[i] = MpcCore.decrypt(resultLHS);
            numbersRHS[i] = MpcCore.decrypt(resultRHS);
        }
    }

    function mulTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.mul(gtA, gtB));

            assert(numbers[i] == MpcCore.decrypt(MpcCore.mul(a[i], gtB)));
            assert(numbers[i] == MpcCore.decrypt(MpcCore.mul(gtA, b[i])));
        }
    }

    function checkedMulTest(uint128 a, uint128 b) public {
        _resetNumbers(1);

        gtUint128 memory gtA = MpcCore.setPublic128(a);
        gtUint128 memory gtB = MpcCore.setPublic128(b);

        numbers[0] = MpcCore.decrypt(MpcCore.checkedMul(gtA, gtB));

        assert(numbers[0] == MpcCore.decrypt(MpcCore.checkedMul(a, gtB)));
        assert(numbers[0] == MpcCore.decrypt(MpcCore.checkedMul(gtA, b)));
    }

    function checkedMulWithOverflowBitTest(uint128[] calldata a, uint128[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetOverflows(a.length);
        _resetOverflowsLHS(a.length);
        _resetOverflowsRHS(a.length);
        _resetNumbers(a.length);
        _resetNumbersLHS(a.length);
        _resetNumbersRHS(a.length);

        gtBool bit;
        gtBool bitLHS;
        gtBool bitRHS;
        gtUint128 memory result;
        gtUint128 memory resultLHS;
        gtUint128 memory resultRHS;

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b[i]);
            
            (bit, result) = MpcCore.checkedMulWithOverflowBit(gtA, gtB);
            (bitLHS, resultLHS) = MpcCore.checkedMulWithOverflowBit(a[i], gtB);
            (bitRHS, resultRHS) = MpcCore.checkedMulWithOverflowBit(gtA, b[i]);

            overflows[i] = MpcCore.decrypt(bit);
            overflowsLHS[i] = MpcCore.decrypt(bitLHS);
            overflowsRHS[i] = MpcCore.decrypt(bitRHS);
            numbers[i] = MpcCore.decrypt(result);
            numbersLHS[i] = MpcCore.decrypt(resultLHS);
            numbersRHS[i] = MpcCore.decrypt(resultRHS);
        }
    }

    function _resetOverflows(uint256 length) internal {
        // Reset the overflows array
        delete overflows;
        
        // Resize the overflows array to match input length
        for(uint i = 0; i < length; i++) {
            overflows.push(false);
        }
    }

    function _resetOverflowsLHS(uint256 length) internal {
        // Reset the overflows array
        delete overflowsLHS;
        
        // Resize the overflows array to match input length
        for(uint i = 0; i < length; i++) {
            overflowsLHS.push(false);
        }
    }

    function _resetOverflowsRHS(uint256 length) internal {
        // Reset the overflows array
        delete overflowsRHS;
        
        // Resize the overflows array to match input length
        for(uint i = 0; i < length; i++) {
            overflowsRHS.push(false);
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

    function _resetNumbersLHS(uint256 length) internal {
        // Reset the numbers array
        delete numbersLHS;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbersLHS.push(0);
        }
    }

    function _resetNumbersRHS(uint256 length) internal {
        // Reset the numbers array
        delete numbersRHS;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbersRHS.push(0);
        }
    }
}