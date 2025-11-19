// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title ValidateCiphertext128TestsContract
 * @notice Simple contract to test buildInputText with 128-bit values via Wallet.encryptValue
 * @dev Validates itUint128 and returns ctUint128 via offBoardToUser
 */
contract ValidateCiphertext128TestsContract {
    
    // Events
    event ValueValidated(address indexed user, string operation);
    event ValueOffBoarded128(address indexed user, ctUint128 result);
    
    /**
     * @dev Validates an encrypted uint128 input and returns it encrypted for user
     * @param input The encrypted uint128 input (itUint128)
     * @return The encrypted value for the user (ctUint128)
     */
    function validateAndReturn(itUint128 calldata input) external returns (ctUint128) {
        // Validate the ciphertext and convert to gtUint128
        gtUint128 validatedValue = MpcCore.validateCiphertext(input);
        
        emit ValueValidated(msg.sender, "validateAndReturn");
        
        // OffBoard to user (GT → CT for user to decrypt)
        ctUint128 ctResult = MpcCore.offBoardToUser(validatedValue, msg.sender);
        
        emit ValueOffBoarded128(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates and adds two encrypted uint128 values
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @return The result encrypted for the user (ctUint128)
     */
    function validateAndAdd(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        // Validate both inputs
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        emit ValueValidated(msg.sender, "validateAndAdd");
        
        // Perform addition
        gtUint128 result = MpcCore.add(gtA, gtB);
        
        // OffBoard to user
        ctUint128 ctResult = MpcCore.offBoardToUser(result, msg.sender);
        
        emit ValueOffBoarded128(msg.sender, ctResult);
        
        return ctResult;
    }
}
