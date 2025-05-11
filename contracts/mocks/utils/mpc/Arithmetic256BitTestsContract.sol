// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Arithmetic256BitTestsContract {

    enum PrivateInput {
        BOTH,
        LHS,
        RHS
    }

    bool[] public overflows;
    bool[] public overflowsLHS;
    bool[] public overflowsRHS;
    uint256[] public numbers2;
    uint256[] public numbersLHS2;
    uint256[] public numbersRHS2;

    function addTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.add(gtA, gtB));

            assert(numbers2[i] == MpcCore.decrypt(MpcCore.add(a[i], gtB)));
            assert(numbers2[i] == MpcCore.decrypt(MpcCore.add(gtA, b[i])));
        }
    }

    function checkedAddTest(uint256 a, uint256 b) public {
        _resetNumbers2(1);

        gtUint256 memory gtA = MpcCore.setPublic256(a);
        gtUint256 memory gtB = MpcCore.setPublic256(b);

        numbers2[0] = MpcCore.decrypt(MpcCore.checkedAdd(gtA, gtB));

        assert(numbers2[0] == MpcCore.decrypt(MpcCore.checkedAdd(a, gtB)));
        assert(numbers2[0] == MpcCore.decrypt(MpcCore.checkedAdd(gtA, b)));
    }

    function checkedAddWithOverflowBitTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetOverflows(a.length);
        _resetOverflowsLHS(a.length);
        _resetOverflowsRHS(a.length);
        _resetNumbers2(a.length);
        _resetNumbersLHS2(a.length);
        _resetNumbersRHS2(a.length);

        gtBool bit;
        gtBool bitLHS;
        gtBool bitRHS;
        gtUint256 memory result;
        gtUint256 memory resultLHS;
        gtUint256 memory resultRHS;

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            (bit, result) = MpcCore.checkedAddWithOverflowBit(gtA, gtB);
            (bitLHS, resultLHS) = MpcCore.checkedAddWithOverflowBit(a[i], gtB);
            (bitRHS, resultRHS) = MpcCore.checkedAddWithOverflowBit(gtA, b[i]);

            overflows[i] = MpcCore.decrypt(bit);
            overflowsLHS[i] = MpcCore.decrypt(bitLHS);
            overflowsRHS[i] = MpcCore.decrypt(bitRHS);
            numbers2[i] = MpcCore.decrypt(result);
            numbersLHS2[i] = MpcCore.decrypt(resultLHS);
            numbersRHS2[i] = MpcCore.decrypt(resultRHS);
        }
    }

    function subTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            numbers2[i] = MpcCore.decrypt(MpcCore.sub(gtA, gtB));

            assert(numbers2[i] == MpcCore.decrypt(MpcCore.sub(a[i], gtB)));
            assert(numbers2[i] == MpcCore.decrypt(MpcCore.sub(gtA, b[i])));
        }
    }

    function checkedSubTest(uint256 a, uint256 b) public {
        _resetNumbers2(1);

        gtUint256 memory gtA = MpcCore.setPublic256(a);
        gtUint256 memory gtB = MpcCore.setPublic256(b);

        numbers2[0] = MpcCore.decrypt(MpcCore.checkedSub(gtA, gtB));

        assert(numbers2[0] == MpcCore.decrypt(MpcCore.checkedSub(a, gtB)));
        assert(numbers2[0] == MpcCore.decrypt(MpcCore.checkedSub(gtA, b)));
    }

    function checkedSubWithOverflowBitTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetOverflows(a.length);
        _resetOverflowsLHS(a.length);
        _resetOverflowsRHS(a.length);
        _resetNumbers2(a.length);
        _resetNumbersLHS2(a.length);
        _resetNumbersRHS2(a.length);

        gtBool bit;
        gtBool bitLHS;
        gtBool bitRHS;
        gtUint256 memory result;
        gtUint256 memory resultLHS;
        gtUint256 memory resultRHS;

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            (bit, result) = MpcCore.checkedSubWithOverflowBit(gtA, gtB);
            (bitLHS, resultLHS) = MpcCore.checkedSubWithOverflowBit(a[i], gtB);
            (bitRHS, resultRHS) = MpcCore.checkedSubWithOverflowBit(gtA, b[i]);

            overflows[i] = MpcCore.decrypt(bit);
            overflowsLHS[i] = MpcCore.decrypt(bitLHS);
            overflowsRHS[i] = MpcCore.decrypt(bitRHS);
            numbers2[i] = MpcCore.decrypt(result);
            numbersLHS2[i] = MpcCore.decrypt(resultLHS);
            numbersRHS2[i] = MpcCore.decrypt(resultRHS);
        }
    }

    function mulTest(uint256[] calldata a, uint256[] calldata b, PrivateInput privateInput) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            if (privateInput == PrivateInput.BOTH) {
                numbers2[i] = MpcCore.decrypt(MpcCore.mul(gtA, gtB));
            } else if (privateInput == PrivateInput.LHS) {
                numbers2[i] = MpcCore.decrypt(MpcCore.mul(gtA, b[i]));
            } else if (privateInput == PrivateInput.RHS) {
                numbers2[i] = MpcCore.decrypt(MpcCore.mul(a[i], gtB));
            }
        }
    }

    function checkedMulTest(uint256 a, uint256 b, PrivateInput privateInput) public {
        _resetNumbers2(1);

        gtUint256 memory gtA = MpcCore.setPublic256(a);
        gtUint256 memory gtB = MpcCore.setPublic256(b);

        if (privateInput == PrivateInput.BOTH) {
            numbers2[0] = MpcCore.decrypt(MpcCore.checkedMul(gtA, gtB));
        } else if (privateInput == PrivateInput.LHS) {
            numbers2[0] = MpcCore.decrypt(MpcCore.checkedMul(gtA, b));
        } else if (privateInput == PrivateInput.RHS) {
            numbers2[0] = MpcCore.decrypt(MpcCore.checkedMul(a, gtB));
        }
    }

    function checkedMulWithOverflowBitTest(uint256[] calldata a, uint256[] calldata b, PrivateInput privateInput) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetOverflows(a.length);
        _resetNumbers2(a.length);

        gtBool bit;
        gtUint256 memory result;

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            if (privateInput == PrivateInput.BOTH) {
                (bit, result) = MpcCore.checkedMulWithOverflowBit(gtA, gtB);
            } else if (privateInput == PrivateInput.LHS) {
                (bit, result) = MpcCore.checkedMulWithOverflowBit(a[i], gtB);
            } else if (privateInput == PrivateInput.RHS) {
                (bit, result) = MpcCore.checkedMulWithOverflowBit(gtA, b[i]);
            }

            overflows[i] = MpcCore.decrypt(bit);
            numbers2[i] = MpcCore.decrypt(result);
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

    function _resetNumbers2(uint256 length) internal {
        // Reset the numbers array
        delete numbers2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbers2.push(0);
        }
    }

    function _resetNumbersLHS2(uint256 length) internal {
        // Reset the numbers array
        delete numbersLHS2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbersLHS2.push(0);
        }
    }

    function _resetNumbersRHS2(uint256 length) internal {
        // Reset the numbers array
        delete numbersRHS2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbersRHS2.push(0);
        }
    }
}