// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title MpcOperationsTestContract
 * @dev Contract to test various MPC operations with offBoardToUser functionality
 * This allows users to decrypt the results of operations performed on encrypted values
 */
contract MpcOperationsTestContract {
    
    // Events for tracking operations
    event OperationPerformed(string operation, address indexed user);
    event ValueOffBoarded(address indexed user, ctUint256 result);
    
    /**
     * @dev Add two encrypted 256-bit values and return result encrypted for user
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function add256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.add(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("add256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Subtract two encrypted 256-bit values and return result encrypted for user
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)  
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function sub256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.sub(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("sub256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Multiply two encrypted 256-bit values and return result encrypted for user
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function mul256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.mul(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("mul256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Divide two encrypted 256-bit values and return result encrypted for user
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function div256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.div(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("div256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Get remainder of division and return result encrypted for user
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function rem256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.rem(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("rem256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Perform AND operation on two encrypted 256-bit values
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function and256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.and(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("and256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Perform OR operation on two encrypted 256-bit values
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function or256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.or(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("or256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Perform XOR operation on two encrypted 256-bit values
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function xor256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.xor(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("xor256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Shift left operation on encrypted 256-bit value
     * @param a Encrypted value to shift (itUint256)
     * @param bits Number of bits to shift (plain, must be uint8)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function shl256(itUint256 memory a, uint8 bits, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        
        gtUint256 result = MpcCore.shl(gtA, bits);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("shl256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Shift right operation on encrypted 256-bit value
     * @param a Encrypted value to shift (itUint256)
     * @param bits Number of bits to shift (plain, must be uint8)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function shr256(itUint256 memory a, uint8 bits, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        
        gtUint256 result = MpcCore.shr(gtA, bits);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("shr256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Check if two encrypted values are equal
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256) - 1 if equal, 0 otherwise
     */
    function eq256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtBool result = MpcCore.eq(gtA, gtB);
        gtUint256 resultAsUint = MpcCore.mux(result, MpcCore.setPublic256(1), MpcCore.setPublic256(0));
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(resultAsUint, user);
        
        emit OperationPerformed("eq256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Check if first value is greater than second
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256) - 1 if a > b, 0 otherwise
     */
    function gt256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtBool result = MpcCore.gt(gtA, gtB);
        gtUint256 resultAsUint = MpcCore.mux(result, MpcCore.setPublic256(1), MpcCore.setPublic256(0));
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(resultAsUint, user);
        
        emit OperationPerformed("gt256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Check if first value is less than second
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256) - 1 if a < b, 0 otherwise
     */
    function lt256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtBool result = MpcCore.lt(gtA, gtB);
        gtUint256 resultAsUint = MpcCore.mux(result, MpcCore.setPublic256(1), MpcCore.setPublic256(0));
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(resultAsUint, user);
        
        emit OperationPerformed("lt256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Get minimum of two encrypted values
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function min256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.min(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("min256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
    /**
     * @dev Get maximum of two encrypted values
     * @param a First encrypted value (itUint256)
     * @param b Second encrypted value (itUint256)
     * @param user Address to encrypt result for
     * @return Result encrypted for the user (ctUint256)
     */
    function max256(itUint256 memory a, itUint256 memory b, address user) public returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.max(gtA, gtB);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(result, user);
        
        emit OperationPerformed("max256", user);
        emit ValueOffBoarded(user, ctResult);
        
        return ctResult;
    }
    
}

