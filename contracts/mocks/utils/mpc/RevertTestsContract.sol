// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract RevertTestsContract {

    // Test 1: Simple revert with a string
    function simpleRevertWithString() public pure {
        revert("This is a simple revert with a string message");
    }

    // Test 2: Require depending on function arg with a string
    function requireWithArg(bool shouldPass) public pure {
        require(shouldPass, "Require failed: argument condition not met");
    }

    // Test 3: Require that is calculated from an encrypted and validated arg (validateCiphertext)
    function requireWithValidatedCiphertext(itBool calldata encryptedBool) public {
        gtBool validatedBool = MpcCore.validateCiphertext(encryptedBool);
        bool decryptedBool = MpcCore.decrypt(validatedBool);
        require(decryptedBool, "Require failed: validated ciphertext condition not met");
    }

    // Test 4a: Require with encrypted boolean from setPublic
    function requireWithSetPublicBool(bool inputBool) public {
        gtBool encryptedBool = MpcCore.setPublic(inputBool);
        bool decryptedBool = MpcCore.decrypt(encryptedBool);
        require(decryptedBool, "Require failed: setPublic boolean condition not met");
    }

    // Test 4b: Require with encrypted number from setPublic
    function requireWithSetPublicNumber(uint8 inputNumber) public {
        gtUint8 encryptedNumber = MpcCore.setPublic8(inputNumber);
        uint8 decryptedNumber = MpcCore.decrypt(encryptedNumber);
        require(decryptedNumber > 50, "Require failed: setPublic number condition not met (must be > 50)");
    }

    // Additional test: Require with encrypted number from setPublic using int8
    function requireWithSetPublicSignedNumber(int8 inputNumber) public {
        gtInt8 encryptedNumber = MpcCore.setPublic8(inputNumber);
        int8 decryptedNumber = MpcCore.decrypt(encryptedNumber);
        require(decryptedNumber > 0, "Require failed: setPublic signed number condition not met (must be > 0)");
    }

    // Additional test: Complex require with multiple encrypted values
    function requireWithMultipleEncryptedValues(bool boolVal, uint8 numVal) public {
        gtBool encryptedBool = MpcCore.setPublic(boolVal);
        gtUint8 encryptedNumber = MpcCore.setPublic8(numVal);
        
        bool decryptedBool = MpcCore.decrypt(encryptedBool);
        uint8 decryptedNumber = MpcCore.decrypt(encryptedNumber);
        
        require(decryptedBool && decryptedNumber > 25, "Require failed: complex condition not met (bool must be true AND number > 25)");
    }
}
