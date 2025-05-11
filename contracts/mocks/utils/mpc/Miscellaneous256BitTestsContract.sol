// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Miscellaneous256BitTestsContract {

    uint256[] public numbers2;
    ctUint256[] public ctNumbers2;
    uint256[] public a2;
    uint256[] public b2;
    bool[] public success;
    uint256[] public allowance2;

    function validateCiphertextTest(itUint256[] calldata a_) public {
        _resetNumbers2(a_.length);

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint256 memory gtA = MpcCore.validateCiphertext(a_[i]);
            
            numbers2[i] = MpcCore.decrypt(gtA);
        }
    }

    function setPublicTest(uint256[] calldata a_) public {
        _resetNumbers2(a_.length);

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a_[i]);
            
            numbers2[i] = MpcCore.decrypt(gtA);
        }
    }

    function offBoardToUserTest(uint256[] calldata a_) public {
        _resetCtNumbers2(a_.length);

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a_[i]);
            
            ctNumbers2[i] = MpcCore.offBoardToUser(gtA, msg.sender);
        }
    }

    function randTest2(uint256 length) public {
        _resetNumbers2(length);

        for (uint256 i = 0; i < length; ++i) {
            numbers2[i] = MpcCore.decrypt(MpcCore.rand256());
        }
    }

    function randBoundedBitsTest2(uint8[] calldata numBits) public {
        _resetNumbers2(numBits.length);

        for (uint256 i = 0; i < numBits.length; ++i) {
            numbers2[i] = MpcCore.decrypt(MpcCore.randBoundedBits256(numBits[i]));
        }
    }

    function transferTest(
        uint256[] calldata a_,
        uint256[] calldata b_,
        uint256[] calldata amount_
    )
        public
    {
        require(a_.length == b_.length && a_.length == amount_.length, "Input length mismatch");

        _resetA2(a_.length);
        _resetB2(a_.length);
        _resetSuccess(a_.length);

        gtBool gtSuccess;

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a_[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b_[i]);
            gtUint256 memory gtAmount = MpcCore.setPublic256(amount_[i]);
            
            (gtA, gtB, gtSuccess) = MpcCore.transfer(gtA, gtB, gtAmount);

            a2[i] = MpcCore.decrypt(gtA);
            b2[i] = MpcCore.decrypt(gtB);
            success[i] = MpcCore.decrypt(gtSuccess);
        }
    }

    function transferWithAllowanceTest(
        uint256[] calldata a_,
        uint256[] calldata b_,
        uint256[] calldata amount_,
        uint256[] calldata allowance_
    )
        public
    {
        require(
            a_.length == b_.length &&
            a_.length == amount_.length &&
            a_.length == allowance_.length,
            "Input length mismatch"
        );

        _resetA2(a_.length);
        _resetB2(a_.length);
        _resetSuccess(a_.length);
        _resetAllowance2(a_.length);

        gtBool gtSuccess;

        for (uint256 i = 0; i < a_.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a_[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b_[i]);
            gtUint256 memory gtAmount = MpcCore.setPublic256(amount_[i]);
            gtUint256 memory gtAllowance = MpcCore.setPublic256(allowance_[i]);
            
            (gtA, gtB, gtSuccess, gtAllowance) = MpcCore.transferWithAllowance(gtA, gtB, gtAmount, gtAllowance);

            a2[i] = MpcCore.decrypt(gtA);
            b2[i] = MpcCore.decrypt(gtB);
            success[i] = MpcCore.decrypt(gtSuccess);
            allowance2[i] = MpcCore.decrypt(gtAllowance);
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

    function _resetCtNumbers2(uint256 length) internal {
        // Reset the numbers array
        delete ctNumbers2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            ctNumbers2.push(
                ctUint256(
                    ctUint128(ctUint64.wrap(0), ctUint64.wrap(0)),
                    ctUint128(ctUint64.wrap(0), ctUint64.wrap(0))
                )
            );
        }
    }

    function _resetA2(uint256 length) internal {
        // Reset the numbers array
        delete a2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            a2.push(0);
        }
    }

    function _resetB2(uint256 length) internal {
        // Reset the numbers array
        delete b2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            b2.push(0);
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

    function _resetAllowance2(uint256 length) internal {
        // Reset the numbers array
        delete allowance2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            allowance2.push(0);
        }
    }
}