// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title MpcOperations128TestContract
 * @dev Contract to test uint128 MPC operations with offBoardToUser functionality
 * This allows users to decrypt the results of operations performed on encrypted uint128 values
 */
contract MpcOperations128TestContract {
    
    // Events for tracking operations
    event OperationPerformed(string operation, address indexed user);
    event ValueOffBoarded128(address indexed user, ctUint128 result);
    
    /**
     * @dev Add two encrypted 128-bit values and return result encrypted for user
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function add128(itUint128 memory a, itUint128 memory b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.add(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("add128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Subtract two encrypted 128-bit values and return result encrypted for user
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)  
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function sub128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.sub(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("sub128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Multiply two encrypted 128-bit values and return result encrypted for user
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function mul128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.mul(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("mul128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Divide two encrypted 128-bit values and return result encrypted for user
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function div128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.div(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("div128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Get remainder of division and return result encrypted for user
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function rem128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.rem(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("rem128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Perform AND operation on two encrypted 128-bit values
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function and128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.and(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("and128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Perform OR operation on two encrypted 128-bit values
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function or128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.or(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("or128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Perform XOR operation on two encrypted 128-bit values
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function xor128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.xor(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("xor128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Shift left operation on encrypted 128-bit value
     * @param a Encrypted value to shift (itUint128)
     * @param bits Number of bits to shift (plain, must be uint8)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function shl128(itUint128 calldata a, uint8 bits, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        
        gtUint128 result = MpcCore.shl(gtA, bits);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("shl128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Shift right operation on encrypted 128-bit value
     * @param a Encrypted value to shift (itUint128)
     * @param bits Number of bits to shift (plain, must be uint8)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function shr128(itUint128 calldata a, uint8 bits, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        
        gtUint128 result = MpcCore.shr(gtA, bits);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("shr128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Get minimum of two encrypted values
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function min128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.min(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("min128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Get maximum of two encrypted values
     * @param a First encrypted value (itUint128)
     * @param b Second encrypted value (itUint128)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint128)
     */
    function max128(itUint128 calldata a, itUint128 calldata b, address user) public returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.max(gtA, gtB);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("max128", user);
        emit ValueOffBoarded128(user, ctResult);
        
        return ctResult;
    }
}

