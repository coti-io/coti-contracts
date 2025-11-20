// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PrivacyProxy
 * @notice Simple upgradeable proxy that delegates all calls to an implementation contract
 * @dev Tests if IT-type validation works through delegatecall
 */
contract PrivacyProxy {
    
    // Storage slot for implementation address (EIP-1967)
    bytes32 private constant IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    
    // Storage slot for admin address
    bytes32 private constant ADMIN_SLOT = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
    
    // Events
    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);
    
    /**
     * @notice Constructor sets initial implementation and admin
     */
    constructor(address _implementation) {
        _setImplementation(_implementation);
        _setAdmin(msg.sender);
    }
    
    /**
     * @notice Modifier to restrict functions to admin only
     */
    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "PrivacyProxy: caller is not admin");
        _;
    }
    
    /**
     * @notice Upgrade to a new implementation
     * @param newImplementation Address of the new implementation contract
     */
    function upgradeTo(address newImplementation) external onlyAdmin {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }
    
    /**
     * @notice Change the admin
     * @param newAdmin Address of the new admin
     */
    function changeAdmin(address newAdmin) external onlyAdmin {
        address oldAdmin = _getAdmin();
        _setAdmin(newAdmin);
        emit AdminChanged(oldAdmin, newAdmin);
    }
    
    /**
     * @notice Get current implementation address
     */
    function implementation() external view returns (address) {
        return _getImplementation();
    }
    
    /**
     * @notice Get current admin address
     */
    function admin() external view returns (address) {
        return _getAdmin();
    }
    
    /**
     * @notice Fallback function delegates all calls to implementation
     */
    fallback() external payable {
        address impl = _getImplementation();
        require(impl != address(0), "PrivacyProxy: implementation not set");
        
        assembly {
            // Copy msg.data to memory
            calldatacopy(0, 0, calldatasize())
            
            // Delegatecall to implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            
            // Copy return data
            returndatacopy(0, 0, returndatasize())
            
            // Return or revert based on delegatecall result
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
    
    /**
     * @notice Receive function for ETH transfers
     */
    receive() external payable {}
    
    // Internal functions
    
    function _setImplementation(address newImplementation) private {
        require(newImplementation != address(0), "PrivacyProxy: invalid implementation");
        
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }
    
    function _getImplementation() private view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }
    
    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "PrivacyProxy: invalid admin");
        
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }
    
    function _getAdmin() private view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }
}

