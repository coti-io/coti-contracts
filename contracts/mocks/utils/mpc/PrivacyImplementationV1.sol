// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title PrivacyImplementationV1
 * @notice Implementation contract with privacy-preserving operations
 * @dev To be used behind PrivacyProxy via delegatecall
 */
contract PrivacyImplementationV1 {
    
    // Storage layout must match proxy if needed
    // Using mapping to avoid storage slot conflicts with proxy
    mapping(address => gtUint128) private userBalances128;
    mapping(address => gtUint256) private userBalances256;
    
    // Events
    event ValueStored128(address indexed user);
    event ValueStored256(address indexed user);
    event OperationPerformed(address indexed user, string operation);
    
    /**
     * @notice Store encrypted uint128 value for user
     * @dev IT-type validation happens in delegatecall context
     */
    function storeValue128(itUint128 calldata value) external returns (ctUint128) {
        // Validate IT-type (this runs in proxy's context via delegatecall)
        gtUint128 gtValue = MpcCore.validateCiphertext(value);
        
        // Store in user's balance
        userBalances128[msg.sender] = gtValue;
        
        emit ValueStored128(msg.sender);
        
        // Return encrypted for user
        return MpcCore.offBoardToUser(gtValue, msg.sender);
    }
    
    /**
     * @notice Add to user's stored value (uint128)
     */
    function addToBalance128(itUint128 calldata amount) external returns (ctUint128) {
        // Validate new amount
        gtUint128 gtAmount = MpcCore.validateCiphertext(amount);
        
        // Get current balance
        gtUint128 currentBalance = userBalances128[msg.sender];
        
        // Add to balance
        gtUint128 newBalance = MpcCore.add(currentBalance, gtAmount);
        
        // Store new balance
        userBalances128[msg.sender] = newBalance;
        
        emit OperationPerformed(msg.sender, "add128");
        
        // Return encrypted result
        return MpcCore.offBoardToUser(newBalance, msg.sender);
    }
    
    /**
     * @notice Get user's balance (uint128)
     */
    function getBalance128() external returns (ctUint128) {
        gtUint128 balance = userBalances128[msg.sender];
        return MpcCore.offBoardToUser(balance, msg.sender);
    }
    
    /**
     * @notice Perform addition on two encrypted values (uint128)
     */
    function add128(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.add(gtA, gtB);
        
        emit OperationPerformed(msg.sender, "add128");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Perform multiplication on two encrypted values (uint128)
     */
    function mul128(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 result = MpcCore.mul(gtA, gtB);
        
        emit OperationPerformed(msg.sender, "mul128");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Store encrypted uint256 value for user
     */
    function storeValue256(itUint256 calldata value) external returns (ctUint256 memory) {
        gtUint256 gtValue = MpcCore.validateCiphertext(value);
        
        userBalances256[msg.sender] = gtValue;
        
        emit ValueStored256(msg.sender);
        
        return MpcCore.offBoardToUser(gtValue, msg.sender);
    }
    
    /**
     * @notice Add to user's stored value (uint256)
     */
    function addToBalance256(itUint256 calldata amount) external returns (ctUint256 memory) {
        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        
        gtUint256 currentBalance = userBalances256[msg.sender];
        
        gtUint256 newBalance = MpcCore.add(currentBalance, gtAmount);
        
        userBalances256[msg.sender] = newBalance;
        
        emit OperationPerformed(msg.sender, "add256");
        
        return MpcCore.offBoardToUser(newBalance, msg.sender);
    }
    
    /**
     * @notice Get user's balance (uint256)
     */
    function getBalance256() external returns (ctUint256 memory) {
        gtUint256 balance = userBalances256[msg.sender];
        return MpcCore.offBoardToUser(balance, msg.sender);
    }
    
    /**
     * @notice Perform addition on two encrypted values (uint256)
     */
    function add256(itUint256 calldata a, itUint256 calldata b) external returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 result = MpcCore.add(gtA, gtB);
        
        emit OperationPerformed(msg.sender, "add256");
        
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Get version of implementation
     */
    function version() external pure returns (string memory) {
        return "v1";
    }
}

