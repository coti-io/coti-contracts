// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";
import "./CrossContractTargetContract.sol";

/**
 * @title CrossContractProxyContract
 * @notice Proxy contract that accepts IT-type from users and calls target contracts with GT-type
 * @dev This contract demonstrates the pattern:
 *      User → Proxy (IT-type) → Target (GT-type) → Proxy (stores result) → User (decrypts)
 */
contract CrossContractProxyContract {
    
    // Reference to target contract
    CrossContractTargetContract public targetContract;
    
    // Storage for results (mapping user address → operation → result)
    mapping(address => mapping(string => gtUint128)) public storedResults128;
    mapping(address => mapping(string => gtUint256)) public storedResults256;
    
    // Events
    event ProxyCallCompleted(address indexed user, string operation, address targetContract);
    event ResultStored(address indexed user, string operation);
    event ResultDecrypted(address indexed user, string operation);
    
    constructor(address _targetContract) {
        targetContract = CrossContractTargetContract(_targetContract);
    }
    
    /**
     * @notice Proxy call: User sends IT-type, we validate, call target, store result
     * @param a First encrypted value (IT-type from user)
     * @param b Second encrypted value (IT-type from user)
     * @param operation Operation identifier for storage
     * @return result Encrypted result for user decryption
     */
    function proxyAdd128(
        itUint128 calldata a,
        itUint128 calldata b,
        string calldata operation
    ) external returns (ctUint128) {
        // Step 1: Validate ciphertexts (IT-type → GT-type)
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        // Step 2: Call target contract with GT-type values
        gtUint128 gtResult = targetContract.add128(gtA, gtB);
        
        // Step 3: Store result for this user
        storedResults128[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        // Step 4: Return result encrypted for user via offBoardToUser
        ctUint128 ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Proxy call for multiplication
     */
    function proxyMul128(
        itUint128 calldata a,
        itUint128 calldata b,
        string calldata operation
    ) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 gtResult = targetContract.mul128(gtA, gtB);
        
        storedResults128[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Proxy call for subtraction
     */
    function proxySub128(
        itUint128 calldata a,
        itUint128 calldata b,
        string calldata operation
    ) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        
        gtUint128 gtResult = targetContract.sub128(gtA, gtB);
        
        storedResults128[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Proxy call for complex operation: (a + b) * c
     */
    function proxyComplexOperation128(
        itUint128 calldata a,
        itUint128 calldata b,
        itUint128 calldata c,
        string calldata operation
    ) external returns (ctUint128) {
        gtUint128 gtA = MpcCore.validateCiphertext(a);
        gtUint128 gtB = MpcCore.validateCiphertext(b);
        gtUint128 gtC = MpcCore.validateCiphertext(c);
        
        gtUint128 gtResult = targetContract.complexOperation128(gtA, gtB, gtC);
        
        storedResults128[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        ctUint128 ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Get stored result and decrypt it for user (uint128)
     * @param operation Operation identifier
     * @return Encrypted result for user decryption
     */
    function getStoredResult128(string calldata operation) external returns (ctUint128) {
        gtUint128 storedResult = storedResults128[msg.sender][operation];
        
        return MpcCore.offBoardToUser(storedResult, msg.sender);
    }
    
    /**
     * @notice Proxy call for uint256 addition
     */
    function proxyAdd256(
        itUint256 calldata a,
        itUint256 calldata b,
        string calldata operation
    ) external returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 gtResult = targetContract.add256(gtA, gtB);
        
        storedResults256[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Proxy call for uint256 multiplication
     */
    function proxyMul256(
        itUint256 calldata a,
        itUint256 calldata b,
        string calldata operation
    ) external returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        gtUint256 gtResult = targetContract.mul256(gtA, gtB);
        
        storedResults256[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Proxy call for complex uint256 operation
     */
    function proxyComplexOperation256(
        itUint256 calldata a,
        itUint256 calldata b,
        itUint256 calldata c,
        string calldata operation
    ) external returns (ctUint256 memory) {
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        gtUint256 gtC = MpcCore.validateCiphertext(c);
        
        gtUint256 gtResult = targetContract.complexOperation256(gtA, gtB, gtC);
        
        storedResults256[msg.sender][operation] = gtResult;
        emit ResultStored(msg.sender, operation);
        
        ctUint256 memory ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        emit ProxyCallCompleted(msg.sender, operation, address(targetContract));
        
        return ctResult;
    }
    
    /**
     * @notice Get stored result and decrypt it for user (uint256)
     * @param operation Operation identifier
     * @return Encrypted result for user decryption
     */
    function getStoredResult256(string calldata operation) external returns (ctUint256 memory) {
        gtUint256 storedResult = storedResults256[msg.sender][operation];
        
        return MpcCore.offBoardToUser(storedResult, msg.sender);
    }
}

