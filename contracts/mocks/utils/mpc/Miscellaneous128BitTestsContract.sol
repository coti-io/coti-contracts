// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Miscellaneous128BitTestsContract {

    uint128[] public numbers;
    ctUint128[] public ctNumbers;
    uint128[] public a;
    uint128[] public b;
    bool[] public success;
    uint128[] public allowance;

    function validateCiphertextTest(itUint128[] calldata a_) public {
        _resetNumbers(a_.length);

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint128 memory gtA = MpcCore.validateCiphertext(a_[i]);
            
            numbers[i] = MpcCore.decrypt(gtA);
        }
    }

    function setPublicTest(uint128[] calldata a_) public {
        _resetNumbers(a_.length);

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a_[i]);
            
            numbers[i] = MpcCore.decrypt(gtA);
        }
    }

    function offBoardToUserTest(uint128[] calldata a_) public {
        _resetCtNumbers(a_.length);

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a_[i]);
            
            ctNumbers[i] = MpcCore.offBoardToUser(gtA, msg.sender);
        }
    }

    function randTest(uint256 length) public {
        _resetNumbers(length);

        for (uint256 i = 0; i < length; ++i) {
            numbers[i] = MpcCore.decrypt(MpcCore.rand128());
        }
    }

    function randBoundedBitsTest(uint8[] calldata numBits) public {
        _resetNumbers(numBits.length);

        for (uint256 i = 0; i < numBits.length; ++i) {
            numbers[i] = MpcCore.decrypt(MpcCore.randBoundedBits128(numBits[i]));
        }
    }

    function transferTest(
        uint128[] calldata a_,
        uint128[] calldata b_,
        uint128[] calldata amount_
    )
        public
    {
        require(a_.length == b_.length && a_.length == amount_.length, "Input length mismatch");

        _resetA(a_.length);
        _resetB(a_.length);
        _resetSuccess(a_.length);

        gtBool gtSuccess;

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a_[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b_[i]);
            gtUint128 memory gtAmount = MpcCore.setPublic128(amount_[i]);
            
            (gtA, gtB, gtSuccess) = MpcCore.transfer(gtA, gtB, gtAmount);

            a[i] = MpcCore.decrypt(gtA);
            b[i] = MpcCore.decrypt(gtB);
            success[i] = MpcCore.decrypt(gtSuccess);
        }
    }

    function transferWithAllowanceTest(
        uint128[] calldata a_,
        uint128[] calldata b_,
        uint128[] calldata amount_,
        uint128[] calldata allowance_
    )
        public
    {
        require(
            a_.length == b_.length &&
            a_.length == amount_.length &&
            a_.length == allowance_.length,
            "Input length mismatch"
        );

        _resetA(a_.length);
        _resetB(a_.length);
        _resetSuccess(a_.length);
        _resetAllowance(a_.length);

        gtBool gtSuccess;

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint128 memory gtA = MpcCore.setPublic128(a_[i]);
            gtUint128 memory gtB = MpcCore.setPublic128(b_[i]);
            gtUint128 memory gtAmount = MpcCore.setPublic128(amount_[i]);
            gtUint128 memory gtAllowance = MpcCore.setPublic128(allowance_[i]);
            
            (gtA, gtB, gtSuccess, gtAllowance) = MpcCore.transferWithAllowance(gtA, gtB, gtAmount, gtAllowance);

            a[i] = MpcCore.decrypt(gtA);
            b[i] = MpcCore.decrypt(gtB);
            success[i] = MpcCore.decrypt(gtSuccess);
            allowance[i] = MpcCore.decrypt(gtAllowance);
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

    function _resetCtNumbers(uint256 length) internal {
        // Reset the numbers array
        delete ctNumbers;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            ctNumbers.push(ctUint128(ctUint64.wrap(0), ctUint64.wrap(0)));
        }
    }

    function _resetA(uint256 length) internal {
        // Reset the numbers array
        delete a;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            a.push(0);
        }
    }

    function _resetB(uint256 length) internal {
        // Reset the numbers array
        delete b;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            b.push(0);
        }
    }

    function _resetSuccess(uint256 length) internal {
        // Reset the numbers array
        delete success;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            success.push(false);
        }
    }

    function _resetAllowance(uint256 length) internal {
        // Reset the numbers array
        delete allowance;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            allowance.push(0);
        }
    }
}