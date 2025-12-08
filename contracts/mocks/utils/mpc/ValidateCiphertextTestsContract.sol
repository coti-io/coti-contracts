// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title ValidateCiphertextTestsContract
 * @notice Contract to test validateCiphertext for 8/16/32/64-bit values
 * @dev Validates itUint (8/16/32/64-bit) and returns ctUint via offBoardToUser
 */
contract ValidateCiphertextTestsContract {
    
    // Events
    event ValueValidated(address indexed user, string operation);
    event ValueOffBoarded(address indexed user, ctUint8 result);
    
    uint8 storedValue;
    bool validationResult;
    ctUint8 storedEncryptedValue;
    
    function getStoredValue() public view returns (uint8) {
        return storedValue;
    }
    
    function getValidationResult() public view returns (bool) {
        return validationResult;
    }
    
    function getStoredEncryptedValue() public view returns (ctUint8) {
        return storedEncryptedValue;
    }
    
    /**
     * @dev Validates an encrypted uint8 input and returns it encrypted for user
     * @param input The encrypted input (itUint8)
     * @return The encrypted value for the user (ctUint8)
     */
    function validateAndReturn(itUint8 calldata input) external returns (ctUint8) {
        // Validate the ciphertext and convert to gtUint8
        gtUint8 validatedValue = MpcCore.validateCiphertext(input);
        
        emit ValueValidated(msg.sender, "validateAndReturn");
        
        // OffBoard to user (GT → CT for user to decrypt)
        ctUint8 ctResult = MpcCore.offBoardToUser(validatedValue, msg.sender);
        
        emit ValueOffBoarded(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates an encrypted input and stores the decrypted value
     * @param input The encrypted input (itUint8)
     * @return The decrypted uint8 value
     */
    function validateAndStore(itUint8 calldata input) external returns (uint8) {
        // Validate the ciphertext and convert to gtUint8
        gtUint8 validatedValue = MpcCore.validateCiphertext(input);
        
        // Store the encrypted value as ctUint8 (offBoard from gtUint8)
        storedEncryptedValue = MpcCore.offBoard(validatedValue);
        
        // Decrypt the value to store it
        uint8 decryptedValue = MpcCore.decrypt(validatedValue);
        
        storedValue = decryptedValue;
        validationResult = true;
        
        emit ValueValidated(msg.sender, "validateAndStore");
        
        return decryptedValue;
    }
    
    /**
     * @dev Validates and adds two encrypted values
     * @param a First encrypted value (itUint8)
     * @param b Second encrypted value (itUint8)
     * @return The result encrypted for the user (ctUint8)
     */
    function validateAndAdd(itUint8 calldata a, itUint8 calldata b) external returns (ctUint8) {
        // Validate both inputs
        gtUint8 gtA = MpcCore.validateCiphertext(a);
        gtUint8 gtB = MpcCore.validateCiphertext(b);
        
        emit ValueValidated(msg.sender, "validateAndAdd");
        
        // Perform addition
        gtUint8 result = MpcCore.add(gtA, gtB);
        
        // OffBoard to user
        ctUint8 ctResult = MpcCore.offBoardToUser(result, msg.sender);
        
        emit ValueOffBoarded(msg.sender, ctResult);
        
        return ctResult;
    }
}

