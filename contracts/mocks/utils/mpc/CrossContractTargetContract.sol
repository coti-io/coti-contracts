// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/**
 * @title CrossContractTargetContract
 * @notice Target contract that receives encrypted values from proxy contracts
 * @dev This contract demonstrates cross-contract MPC operations where another contract
 *      calls this contract with GT-type values (already validated on-chain)
 */
contract CrossContractTargetContract {
    
    // Events for tracking operations
    event OperationPerformed(string operation, address caller);
    event ValueStored(address indexed user, string operation);
    
    /**
     * @notice Add two encrypted uint128 values (GT-type for cross-contract calls)
     * @param a First encrypted value (gtUint128)
     * @param b Second encrypted value (gtUint128)
     * @return Result as gtUint128
     */
    function add128(gtUint128 a, gtUint128 b) external returns (gtUint128) {
        emit OperationPerformed("add128", msg.sender);
        return MpcCore.add(a, b);
    }
    
    /**
     * @notice Multiply two encrypted uint128 values
     * @param a First encrypted value (gtUint128)
     * @param b Second encrypted value (gtUint128)
     * @return Result as gtUint128
     */
    function mul128(gtUint128 a, gtUint128 b) external returns (gtUint128) {
        emit OperationPerformed("mul128", msg.sender);
        return MpcCore.mul(a, b);
    }
    
    /**
     * @notice Subtract two encrypted uint128 values
     * @param a First encrypted value (gtUint128)
     * @param b Second encrypted value (gtUint128)
     * @return Result as gtUint128
     */
    function sub128(gtUint128 a, gtUint128 b) external returns (gtUint128) {
        emit OperationPerformed("sub128", msg.sender);
        return MpcCore.sub(a, b);
    }
    
    /**
     * @notice Add two encrypted uint256 values (GT-type for cross-contract calls)
     * @param a First encrypted value (gtUint256)
     * @param b Second encrypted value (gtUint256)
     * @return Result as gtUint256
     */
    function add256(gtUint256 a, gtUint256 b) external returns (gtUint256) {
        emit OperationPerformed("add256", msg.sender);
        return MpcCore.add(a, b);
    }
    
    /**
     * @notice Multiply two encrypted uint256 values
     * @param a First encrypted value (gtUint256)
     * @param b Second encrypted value (gtUint256)
     * @return Result as gtUint256
     */
    function mul256(gtUint256 a, gtUint256 b) external returns (gtUint256) {
        emit OperationPerformed("mul256", msg.sender);
        return MpcCore.mul(a, b);
    }
    
    /**
     * @notice Complex operation: (a + b) * c for uint128
     * @param a First encrypted value
     * @param b Second encrypted value
     * @param c Third encrypted value
     * @return Result as gtUint128
     */
    function complexOperation128(gtUint128 a, gtUint128 b, gtUint128 c) external returns (gtUint128) {
        emit OperationPerformed("complexOperation128", msg.sender);
        gtUint128 sum = MpcCore.add(a, b);
        return MpcCore.mul(sum, c);
    }
    
    /**
     * @notice Complex operation: (a + b) * c for uint256
     * @param a First encrypted value
     * @param b Second encrypted value
     * @param c Third encrypted value
     * @return Result as gtUint256
     */
    function complexOperation256(gtUint256 a, gtUint256 b, gtUint256 c) external returns (gtUint256) {
        emit OperationPerformed("complexOperation256", msg.sender);
        gtUint256 sum = MpcCore.add(a, b);
        return MpcCore.mul(sum, c);
    }
}

