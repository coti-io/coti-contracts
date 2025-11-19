// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title ValidateCiphertextSmallTypesContract
 * @notice Contract to test buildInputText with smaller types (uint8, uint16, uint32, uint64)
 * @dev Validates itUint types and returns ctUint via offBoardToUser
 *      Note: buildInputText always encrypts as itUint (128-bit), but we can validate
 *      and use it with smaller types in the contract
 */
contract ValidateCiphertextSmallTypesContract {
    
    // Events for each type
    event ValueValidated8(address indexed user, string operation);
    event ValueOffBoarded8(address indexed user, ctUint8 result);
    
    event ValueValidated16(address indexed user, string operation);
    event ValueOffBoarded16(address indexed user, ctUint16 result);
    
    event ValueValidated32(address indexed user, string operation);
    event ValueOffBoarded32(address indexed user, ctUint32 result);
    
    event ValueValidated64(address indexed user, string operation);
    event ValueOffBoarded64(address indexed user, ctUint64 result);
    
    /**
     * @dev Validates an encrypted uint8 input and returns it encrypted for user
     * @param input The encrypted input (itUint128 from buildInputText, but value fits in uint8)
     * @return The encrypted value for the user (ctUint8)
     */
    function validateAndReturn8(itUint128 calldata input) external returns (ctUint8) {
        // Convert itUint128 to itUint8 (ctUint types are all uint256, so we can cast)
        itUint8 memory it8;
        it8.ciphertext = ctUint8.wrap(ctUint128.unwrap(input.ciphertext));
        it8.signature = input.signature;
        
        // Validate the ciphertext and convert to gtUint8
        gtUint8 validatedValue = MpcCore.validateCiphertext(it8);
        
        emit ValueValidated8(msg.sender, "validateAndReturn8");
        
        // OffBoard to user (GT → CT for user to decrypt)
        ctUint8 ctResult = MpcCore.offBoardToUser(validatedValue, msg.sender);
        
        emit ValueOffBoarded8(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates an encrypted uint16 input and returns it encrypted for user
     * @param input The encrypted input (itUint128 from buildInputText, but value fits in uint16)
     * @return The encrypted value for the user (ctUint16)
     */
    function validateAndReturn16(itUint128 calldata input) external returns (ctUint16) {
        // Convert itUint128 to itUint16
        itUint16 memory it16;
        it16.ciphertext = ctUint16.wrap(ctUint128.unwrap(input.ciphertext));
        it16.signature = input.signature;
        
        // Validate the ciphertext and convert to gtUint16
        gtUint16 validatedValue = MpcCore.validateCiphertext(it16);
        
        emit ValueValidated16(msg.sender, "validateAndReturn16");
        
        // OffBoard to user (GT → CT for user to decrypt)
        ctUint16 ctResult = MpcCore.offBoardToUser(validatedValue, msg.sender);
        
        emit ValueOffBoarded16(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates an encrypted uint32 input and returns it encrypted for user
     * @param input The encrypted input (itUint128 from buildInputText, but value fits in uint32)
     * @return The encrypted value for the user (ctUint32)
     */
    function validateAndReturn32(itUint128 calldata input) external returns (ctUint32) {
        // Convert itUint128 to itUint32
        itUint32 memory it32;
        it32.ciphertext = ctUint32.wrap(ctUint128.unwrap(input.ciphertext));
        it32.signature = input.signature;
        
        // Validate the ciphertext and convert to gtUint32
        gtUint32 validatedValue = MpcCore.validateCiphertext(it32);
        
        emit ValueValidated32(msg.sender, "validateAndReturn32");
        
        // OffBoard to user (GT → CT for user to decrypt)
        ctUint32 ctResult = MpcCore.offBoardToUser(validatedValue, msg.sender);
        
        emit ValueOffBoarded32(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates an encrypted uint64 input and returns it encrypted for user
     * @param input The encrypted input (itUint128 from buildInputText, but value fits in uint64)
     * @return The encrypted value for the user (ctUint64)
     */
    function validateAndReturn64(itUint128 calldata input) external returns (ctUint64) {
        // Convert itUint128 to itUint64
        itUint64 memory it64;
        it64.ciphertext = ctUint64.wrap(ctUint128.unwrap(input.ciphertext));
        it64.signature = input.signature;
        
        // Validate the ciphertext and convert to gtUint64
        gtUint64 validatedValue = MpcCore.validateCiphertext(it64);
        
        emit ValueValidated64(msg.sender, "validateAndReturn64");
        
        // OffBoard to user (GT → CT for user to decrypt)
        ctUint64 ctResult = MpcCore.offBoardToUser(validatedValue, msg.sender);
        
        emit ValueOffBoarded64(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates and adds two encrypted uint8 values
     */
    function validateAndAdd8(itUint128 calldata a, itUint128 calldata b) external returns (ctUint8) {
        // Convert itUint128 to itUint8
        itUint8 memory it8A;
        it8A.ciphertext = ctUint8.wrap(ctUint128.unwrap(a.ciphertext));
        it8A.signature = a.signature;
        
        itUint8 memory it8B;
        it8B.ciphertext = ctUint8.wrap(ctUint128.unwrap(b.ciphertext));
        it8B.signature = b.signature;
        
        gtUint8 gtA = MpcCore.validateCiphertext(it8A);
        gtUint8 gtB = MpcCore.validateCiphertext(it8B);
        
        emit ValueValidated8(msg.sender, "validateAndAdd8");
        
        gtUint8 result = MpcCore.add(gtA, gtB);
        ctUint8 ctResult = MpcCore.offBoardToUser(result, msg.sender);
        
        emit ValueOffBoarded8(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates and adds two encrypted uint16 values
     */
    function validateAndAdd16(itUint128 calldata a, itUint128 calldata b) external returns (ctUint16) {
        // Convert itUint128 to itUint16
        itUint16 memory it16A;
        it16A.ciphertext = ctUint16.wrap(ctUint128.unwrap(a.ciphertext));
        it16A.signature = a.signature;
        
        itUint16 memory it16B;
        it16B.ciphertext = ctUint16.wrap(ctUint128.unwrap(b.ciphertext));
        it16B.signature = b.signature;
        
        gtUint16 gtA = MpcCore.validateCiphertext(it16A);
        gtUint16 gtB = MpcCore.validateCiphertext(it16B);
        
        emit ValueValidated16(msg.sender, "validateAndAdd16");
        
        gtUint16 result = MpcCore.add(gtA, gtB);
        ctUint16 ctResult = MpcCore.offBoardToUser(result, msg.sender);
        
        emit ValueOffBoarded16(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates and adds two encrypted uint32 values
     */
    function validateAndAdd32(itUint128 calldata a, itUint128 calldata b) external returns (ctUint32) {
        // Convert itUint128 to itUint32
        itUint32 memory it32A;
        it32A.ciphertext = ctUint32.wrap(ctUint128.unwrap(a.ciphertext));
        it32A.signature = a.signature;
        
        itUint32 memory it32B;
        it32B.ciphertext = ctUint32.wrap(ctUint128.unwrap(b.ciphertext));
        it32B.signature = b.signature;
        
        gtUint32 gtA = MpcCore.validateCiphertext(it32A);
        gtUint32 gtB = MpcCore.validateCiphertext(it32B);
        
        emit ValueValidated32(msg.sender, "validateAndAdd32");
        
        gtUint32 result = MpcCore.add(gtA, gtB);
        ctUint32 ctResult = MpcCore.offBoardToUser(result, msg.sender);
        
        emit ValueOffBoarded32(msg.sender, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Validates and adds two encrypted uint64 values
     */
    function validateAndAdd64(itUint128 calldata a, itUint128 calldata b) external returns (ctUint64) {
        // Convert itUint128 to itUint64
        itUint64 memory it64A;
        it64A.ciphertext = ctUint64.wrap(ctUint128.unwrap(a.ciphertext));
        it64A.signature = a.signature;
        
        itUint64 memory it64B;
        it64B.ciphertext = ctUint64.wrap(ctUint128.unwrap(b.ciphertext));
        it64B.signature = b.signature;
        
        gtUint64 gtA = MpcCore.validateCiphertext(it64A);
        gtUint64 gtB = MpcCore.validateCiphertext(it64B);
        
        emit ValueValidated64(msg.sender, "validateAndAdd64");
        
        gtUint64 result = MpcCore.add(gtA, gtB);
        ctUint64 ctResult = MpcCore.offBoardToUser(result, msg.sender);
        
        emit ValueOffBoarded64(msg.sender, ctResult);
        
        return ctResult;
    }
}

