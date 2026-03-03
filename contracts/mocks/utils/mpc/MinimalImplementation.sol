// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title MinimalImplementation
 * @notice Test IT-type validation and offBoardToUser with large numbers
 */
contract MinimalImplementation {
    
    // Storage for encrypted result (ctUint256 offBoarded to user)
    mapping(address => ctUint256) public storedCtResult;
    
    event InputsReceived(address indexed user, string message);
    event CalculationDone(address indexed user, string operation);
    event ResultStored(address indexed user, string message);
    
    /**
     * Simple addition test with offBoardToUser storage
     * Flow: IT → validate → GT → add → GT → offBoardToUser → CT → store
     */
    function addAndStore(itUint256 calldata a, itUint256 calldata b) external returns (ctUint256 memory) {
        emit InputsReceived(msg.sender, "Received encrypted inputs");
        
        // Step 1: Validate IT-types (offchain encrypted) → GT-types (onchain encrypted)
        gtUint256 gtA = MpcCore.validateCiphertext(a);
        gtUint256 gtB = MpcCore.validateCiphertext(b);
        
        emit CalculationDone(msg.sender, "Validated ciphertexts");
        
        // Step 2: Add (onchain computation on encrypted values)
        gtUint256 gtResult = MpcCore.add(gtA, gtB);
        
        emit CalculationDone(msg.sender, "Addition completed");
        
        // Step 3: OffBoard to user (GT → CT for user to decrypt)
        ctUint256 memory ctResult = MpcCore.offBoardToUser(gtResult, msg.sender);
        
        // Step 4: Store the CT result
        storedCtResult[msg.sender] = ctResult;
        
        emit ResultStored(msg.sender, "Result stored as ctUint256");
        
        return ctResult;
    }
    
    /**
     * Read stored result from storage
     */
    function getStoredResult() external view returns (ctUint256 memory) {
        return storedCtResult[msg.sender];
    }
}

