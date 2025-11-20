// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract ValidateCiphertext256TestsContract {
    uint256 storedValue;
    bool validationResult;
    ctUint256 storedEncryptedValue;

    function getStoredValue() public view returns (uint256) {
        return storedValue;
    }

    function getValidationResult() public view returns (bool) {
        return validationResult;
    }

    function getStoredEncryptedValue() public view returns (ctUint256 memory) {
        return storedEncryptedValue;
    }

    /**
     * @dev Validates an encrypted uint256 input and stores the decrypted value
     * @param input The encrypted uint256 input (itUint256)
     * @return The decrypted uint256 value
     */
    function validateAndStore(itUint256 memory input) public returns (uint256) {
        // Validate the ciphertext and convert to gtUint256
        gtUint256 validatedValue = MpcCore.validateCiphertext(input);
        
        // Store the encrypted value as ctUint256 (offBoard from gtUint256)
        storedEncryptedValue = MpcCore.offBoard(validatedValue);
        
        // Decrypt the value to store it
        uint256 decryptedValue = MpcCore.decrypt(validatedValue);
        
        storedValue = decryptedValue;
        validationResult = true;
        
        return decryptedValue;
    }

    /**
     * @dev Validates an encrypted uint256 input and performs a simple operation (add 1)
     * @param input The encrypted uint256 input (itUint256)
     * @return The result after adding 1
     */
    function validateAndIncrement(itUint256 memory input) public returns (uint256) {
        // Validate the ciphertext and convert to gtUint256
        gtUint256 validatedValue = MpcCore.validateCiphertext(input);
        
        // Add 1 to the value
        gtUint256 one = MpcCore.setPublic256(1);
        gtUint256 result = MpcCore.add(validatedValue, one);
        
        // Decrypt and return
        uint256 decryptedResult = MpcCore.decrypt(result);
        
        return decryptedResult;
    }
}

