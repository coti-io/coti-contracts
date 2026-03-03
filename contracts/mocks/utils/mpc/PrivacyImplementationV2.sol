// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title PrivacyImplementationV2
 * @notice Upgraded implementation with additional features
 * @dev Storage layout must match V1 to preserve state
 */
contract PrivacyImplementationV2 {
    
    // Storage layout MUST match V1
    mapping(address => gtUint128) private userBalances128;
    mapping(address => gtUint256) private userBalances256;
    
    // Events
    event ValueStored128(address indexed user);
    event ValueStored256(address indexed user);
    event OperationPerformed(address indexed user, string operation);
    
    // V1 functions (must keep same signatures for compatibility)
    
    function storeValue128(itUint128 calldata value) external returns (ctUint128) {
        gtUint128 gtValue = MpcCore.validateCiphertext(value);
        userBalances128[msg.sender] = gtValue;
        emit ValueStored128(msg.sender);
        return MpcCore.offBoardToUser(gtValue, msg.sender);
    }
    
    function addToBalance128(itUint128 calldata amount) external returns (ctUint128) {
        gtUint128 gtAmount = MpcCore.validateCiphertext(amount);
        gtUint128 currentBalance = userBalances128[msg.sender];
        gtUint128 newBalance = MpcCore.add(currentBalance, gtAmount);
        userBalances128[msg.sender] = newBalance;
        emit OperationPerformed(msg.sender, "add128");
        return MpcCore.offBoardToUser(newBalance, msg.sender);
    }
    
    function getBalance128() external returns (ctUint128) {
        gtUint128 balance = userBalances128[msg.sender];
        return MpcCore.offBoardToUser(balance, msg.sender);
    }
    
    function add128(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        gtUint128 result = MpcCore.add(gtA, gtB);
        emit OperationPerformed(msg.sender, "add128");
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    function mul128(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        gtUint128 result = MpcCore.mul(gtA, gtB);
        emit OperationPerformed(msg.sender, "mul128");
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    function storeValue256(itUint256 calldata value) external returns (ctUint256 memory) {
        gtUint256 gtValue = MpcCore.validateCiphertext(value);
        userBalances256[msg.sender] = gtValue;
        emit ValueStored256(msg.sender);
        return MpcCore.offBoardToUser(gtValue, msg.sender);
    }
    
    function addToBalance256(itUint256 calldata amount) external returns (ctUint256 memory) {
        gtUint256 gtAmount = MpcCore.validateCiphertext(amount);
        gtUint256 currentBalance = userBalances256[msg.sender];
        gtUint256 newBalance = MpcCore.add(currentBalance, gtAmount);
        userBalances256[msg.sender] = newBalance;
        emit OperationPerformed(msg.sender, "add256");
        return MpcCore.offBoardToUser(newBalance, msg.sender);
    }
    
    function getBalance256() external returns (ctUint256 memory) {
        gtUint256 balance = userBalances256[msg.sender];
        return MpcCore.offBoardToUser(balance, msg.sender);
    }
    
    function add256(itUint256 calldata a, itUint256 calldata b) external returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        gtUint256 result = MpcCore.add(gtA, gtB);
        emit OperationPerformed(msg.sender, "add256");
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    // NEW V2 FUNCTIONS
    
    /**
     * @notice Subtract from balance (NEW in V2)
     */
    function subtractFromBalance128(itUint128 calldata amount) external returns (ctUint128) {
        gtUint128 gtAmount = MpcCore.validateCiphertext(amount);
        gtUint128 currentBalance = userBalances128[msg.sender];
        gtUint128 newBalance = MpcCore.sub(currentBalance, gtAmount);
        userBalances128[msg.sender] = newBalance;
        emit OperationPerformed(msg.sender, "sub128");
        return MpcCore.offBoardToUser(newBalance, msg.sender);
    }
    
    /**
     * @notice Subtract two encrypted values (NEW in V2)
     */
    function sub128(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        gtUint128 result = MpcCore.sub(gtA, gtB);
        emit OperationPerformed(msg.sender, "sub128");
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Divide two encrypted values (NEW in V2)
     */
    function div128(itUint128 calldata a, itUint128 calldata b) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        gtUint128 result = MpcCore.div(gtA, gtB);
        emit OperationPerformed(msg.sender, "div128");
        return MpcCore.offBoardToUser(result, msg.sender);
    }
    
    /**
     * @notice Get version (upgraded)
     */
    function version() external pure returns (string memory) {
        return "v2";
    }
}

