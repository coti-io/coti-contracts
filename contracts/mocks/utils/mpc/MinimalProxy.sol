// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MinimalProxy
 * @notice Minimal proxy to demonstrate IT-type validation issue
 */
contract MinimalProxy {
    address public implementation;
    
    constructor(address _implementation) {
        implementation = _implementation;
    }
    
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

