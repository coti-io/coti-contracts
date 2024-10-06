// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

abstract contract DataPrivacyFramework {

    // struct needed for avoiding "stack too deep" error
    // see Condition struct for further details
    struct InputData {
        address caller;
        string operation;
        bool active;
        uint256 timestampBefore;
        uint256 timestampAfter;
        bool falseKey;
        bool trueKey;
        uint256 uintParameter;
        address addressParameter;
        string stringParameter;
    }

    struct Condition {
        uint256 id; // numeric ID of the condition
        address caller; // caller associated with this condition
        string operation; // operation associated with this condition
        bool active; // indicates if the permission is active
        bool falseKey; // causes the condition to never be satisfied
        bool trueKey; // causes the permission to always be satisfied (but has lower priority than falseKey)
        uint256 timestampBefore; // condition is valid before this timestamp
        uint256 timestampAfter; // condition is valid after this timestamp
        uint256 uintParameter; // parameter of type uint256 used for verifying if the caller has permission to perform the computation
        address addressParameter; // parameter of type address used for verifying if the caller has permission to perform the computation
        string stringParameter;// parameter of type string used for verifying if the caller has permission to perform the computation
    }

    enum ParameterType {
        None,
        UintParam,
        AddressParam,
        StringParam
    }

    address public constant ADDRESS_ALL = address(1); // used to indicate the generic address (equivalent to "*")

    string public constant STRING_ALL = "*"; // used to indicate the generic string

    bool public addressDefaultPermission; // TODO: Replace with more descriptive name

    bool public operationDefaultPermission; // TODO: Replace with more descriptive name

    mapping(string => bool) public allowedOperations;

    mapping(string => bool) public restrictedOperations;

    mapping(address => uint256) public activePermissions;

    mapping(address => mapping(string => uint256)) public permissions; // caller => operation => idx

    uint256 private _conditionsCount = 1; // we skip ID=0 to allow us to use this value to indicate a null entry

    mapping(uint256 => Condition) public conditions; // idx => conditions

    modifier onlyAllowedUserOperation(string memory operation, uint256 uintParameter, address addressParameter, string memory stringParameter) {
        if (uintParameter != 0) {
            require(this.isOperationAllowed(msg.sender, operation, uintParameter), "DPF: No Permission!");
        } else if (addressParameter != address(0)) {
            require(this.isOperationAllowed(msg.sender, operation, addressParameter), "DPF: No Permission!");
        } else if (keccak256(abi.encodePacked(stringParameter)) != keccak256(abi.encodePacked(""))) {
            require(this.isOperationAllowed(msg.sender, operation, stringParameter), "DPF: No Permission!");
        } else {
            require(this.isOperationAllowed(msg.sender, operation), "DPF: No Permission!");
        }
        
        _;
    }

    /**
     * @param addressDefaultPermission_ default address permission
     * @param operationDefaultPermission_  default operation permission
     */
    constructor(bool addressDefaultPermission_, bool operationDefaultPermission_) {
        addressDefaultPermission = addressDefaultPermission_;
        operationDefaultPermission = operationDefaultPermission_;

        // set admin permissions
        allowedOperations["admin"] = true;

        setPermission(InputData(msg.sender, "admin", true, 0, 0, false, false, 0, address(0), ""));

        // by default we allow all users and all operations
        allowedOperations[STRING_ALL] = true;

        setPermission(InputData(ADDRESS_ALL, STRING_ALL, true, 0, 0, false, false, 0, address(0), ""));
    }

    /**
     * @notice returns the number of rows in the conditions table
     */
    function getConditionsCount() external view returns (uint256) {
        return _conditionsCount - 1;
    }

    /**
     * @notice downloads the entire conditions mapping with paging
     * @dev start with startIdx=1 and increment by chunkSize until the size of the returned array is less than chunk size
     * @dev the developer is responsible for filtering out inactive conditions and conditions that are irrelevant
     * @param startIdx the index of the first condition to include in the list of returned conditions
     * @param chunkSize the maximum number of conditions to return (needed to avoid running out of gas)
     * @return _ array of conditions
     */
    function getConditions(
        uint256 startIdx,
        uint256 chunkSize
    )
        external
        view
        returns (Condition[] memory)
    {
        require(startIdx > 0, "DPF: START_IDX_ZERO");
        require(chunkSize > 0, "DPF: CHUNK_SIZE_ZERO");

        // reached end of table
        if (startIdx >= _conditionsCount) return new Condition[](0);

        // ensures that startIdx + arrSize is not larger than the maximum condition ID
        uint256 arrSize = startIdx + chunkSize - 1 <= _conditionsCount - 1 ? chunkSize : _conditionsCount - startIdx;

        Condition[] memory conditions_ = new Condition[](arrSize);

        for (uint256 i = 0; i < arrSize; i++) {
            conditions_[i] = conditions[startIdx + i];
        }

        return conditions_;
    }

    /**
     * @notice determines whether the provided caller has sufficient permission to perform the given computation
     * @param caller the address of the user who is seeking permission to perform some computation on private data
     * @param operation the operation which the user is seeking to perform
     * @return _ boolean indicating if the user has permission to perform the computation
     */
    function isOperationAllowed(
        address caller,
        string calldata operation
    )
        external
        view
        returns (bool)
    {
        return _isOperationAllowed(
            caller,
            operation,
            ParameterType.None,
            0,
            address(0),
            ""
        );
    }

    /**
     * @notice determines whether the provided caller has sufficient permission to perform the given computation
     * @param caller the address of the user who is seeking permission to perform some computation on private data
     * @param operation the operation which the user is seeking to perform
     * @param uintParameter parameter of type uint256 used to check for permissions
     * @return _ boolean indicating if the user has permission to perform the computation
     */
    function isOperationAllowed(
        address caller,
        string calldata operation,
        uint256 uintParameter
    )
        external
        view
        returns (bool)
    {
        return _isOperationAllowed(
            caller,
            operation,
            ParameterType.UintParam,
            uintParameter,
            address(0),
            ""
        );
    }

    /**
     * @notice determines whether the provided caller has sufficient permission to perform the given computation
     * @param caller the address of the user who is seeking permission to perform some computation on private data
     * @param operation the operation which the user is seeking to perform
     * @param addressParameter parameter of type address used to check for permissions
     * @return _ boolean indicating if the user has permission to perform the computation
     */
    function isOperationAllowed(
        address caller,
        string calldata operation,
        address addressParameter
    )
        external
        view
        returns (bool)
    {
        return _isOperationAllowed(
            caller,
            operation,
            ParameterType.AddressParam,
            0,
            addressParameter,
            ""
        );
    }

    /**
     * @notice determines whether the provided caller has sufficient permission to perform the given computation
     * @param caller the address of the user who is seeking permission to perform some computation on private data
     * @param operation the operation which the user is seeking to perform
     * @param stringParameter parameter of type string used to check for permissions
     * @return _ boolean indicating if the user has permission to perform the computation
     */
    function isOperationAllowed(
        address caller,
        string calldata operation,
        string calldata stringParameter
    )
        external
        view
        returns (bool)
    {
        return _isOperationAllowed(
            caller,
            operation,
            ParameterType.StringParam,
            0,
            address(0),
            stringParameter
        );
    }

    /**
     * @notice updates the default address permission
     * @param defaultPermission new value of the default address permission
     * @return _ boolean indicating if the update succeeded
     */
    function setAddressDefaultPermission(bool defaultPermission) external returns (bool) {
        require(addressDefaultPermission != defaultPermission, "DPF: INVALID_PERMISSION_CHANGE");

        addressDefaultPermission = defaultPermission;
        
        return true;
    }

    /**
     * @notice updates the default operation permission
     * @param defaultPermission new value of the default operation permission
     * @return _ boolean indicating if the update succeeded
     */
    function setOperationDefaultPermission(bool defaultPermission) external returns (bool) {
        require(operationDefaultPermission != defaultPermission, "DPF: INVALID_PERMISSION_CHANGE");

        operationDefaultPermission = defaultPermission;
        
        return true;
    }

    /**
     * @notice sets an operation as "allowed"
     * @param operation the operation to allow
     * @return _ boolean indicating if the update succeeded
     */
    function addAllowedOperation(string memory operation) public returns (bool) {
        require(!allowedOperations[operation], "DPF: OPERATION_ALREADY_ALLOWED");

        allowedOperations[operation] = true;
        
        return true;
    }

    /**
     * @notice removes an "allowed" operation
     * @param operation the operation to remove
     * @return _ boolean indicating if the update succeeded
     */
    function removeAllowedOperation(string calldata operation) external returns (bool) {
        require(allowedOperations[operation], "DPF: OPERATION_NOT_ALLOWED");

        allowedOperations[operation] = false;
        
        return true;
    }

    /**
     * @notice sets an operation as "restricted"
     * @param operation the operation to restrict
     * @return _ boolean indicating if the update succeeded
     */
    function addRestrictedOperation(string memory operation) public returns (bool) {
        require(!restrictedOperations[operation], "DPF: OPERATION_ALREADY_RESTRICTED");

        restrictedOperations[operation] = true;
        
        return true;
    }

    /**
     * @notice removes a "restricted" operation
     * @param operation the operation to remove
     * @return _ boolean indicating if the update succeeded
     */
    function removeRestrictedOperation(string calldata operation) external returns (bool) {
        require(restrictedOperations[operation], "DPF: OPERATION_NOT_RESTRICTED");

        restrictedOperations[operation] = false;
        
        return true;
    }

    /**
     * @notice creates a new permission or overwrites an existing one with the same caller and operation
     * @param inputData struct containing the parameters of the new permission
     * @return _ boolean indicating if the update succeeded
     */
    function setPermission(InputData memory inputData) public returns (bool) {
        if (permissions[inputData.caller][inputData.operation] == 0) {
            permissions[inputData.caller][inputData.operation] = _conditionsCount;

            conditions[_conditionsCount] = Condition(
                _conditionsCount,
                inputData.caller,
                inputData.operation,
                inputData.active,
                inputData.falseKey,
                inputData.trueKey,
                inputData.timestampBefore,
                inputData.timestampAfter,
                inputData.uintParameter,
                inputData.addressParameter,
                inputData.stringParameter
            );

            ++_conditionsCount;
            ++activePermissions[inputData.caller];
        } else {
            Condition storage condition = conditions[permissions[inputData.caller][inputData.operation]];

            // if there is an existing inactive permission and we are activating it then we increment activePermissions[caller]
            if (inputData.active && !condition.active) {
                ++activePermissions[inputData.caller];
            }

            // if there is an existing active permission and we are deactivating it then we decrement activePermissions[caller]
            if (!inputData.active && condition.active) {
                --activePermissions[inputData.caller];
            }

            condition.active = inputData.active;
            condition.timestampBefore = inputData.timestampBefore;
            condition.timestampAfter = inputData.timestampAfter;
            condition.falseKey = inputData.falseKey;
            condition.trueKey = inputData.trueKey;
            condition.uintParameter = inputData.uintParameter;
            condition.addressParameter = inputData.addressParameter;
            condition.stringParameter = inputData.stringParameter;
        }

        return true;
    }

    /**
     * @dev searches for a relevant and active permission and checks if the conditions are satisfied
     * @param caller the address of the user who is seeking permission to perform some computation on private data
     * @param operation the operation which the user is seeking to perform
     * @param parameterType enum indicating the type of paramter we are using for comparison
     * @param uintParameter parameter of type uint256 used to check for permissions
     * @param addressParameter parameter of type address used to check for permissions
     * @param stringParameter parameter of type string used to check for permissions
     * @return _ boolean indicating if the caller has sufficient permission
     */
    function _isOperationAllowed(
        address caller,
        string calldata operation,
        ParameterType parameterType,
        uint256 uintParameter,
        address addressParameter,
        string memory stringParameter
    ) internal view returns (bool) {
        if (restrictedOperations[operation]) return false; // first we check if the operation is restricted
        if (!allowedOperations[STRING_ALL] && !allowedOperations[operation]) return false; // second we check if the operation is allowed
        
        // the provided caller has an active permission for the given operation
        if (conditions[permissions[caller][operation]].active) {
            return _evaluateCondition(
                conditions[permissions[caller][operation]],
                parameterType,
                uintParameter,
                addressParameter,
                stringParameter
            );
        }

        // the provided caller has an active permission for all operations
        if (conditions[permissions[caller][STRING_ALL]].active) {
            return _evaluateCondition(
                conditions[permissions[caller][STRING_ALL]],
                parameterType,
                uintParameter,
                addressParameter,
                stringParameter
            );
        }

        // fallback for when the provided caller has some active permissions but none are matching the given operation
        if (activePermissions[caller] > 0) {
            return operationDefaultPermission;
        }

        // all users are permitted to compute the given operation
        if (conditions[permissions[ADDRESS_ALL][operation]].active) {
            return _evaluateCondition(
                conditions[permissions[ADDRESS_ALL][operation]],
                parameterType,
                uintParameter,
                addressParameter,
                stringParameter
            );
        }

        // all users are permitted to compute all operations
        if (conditions[permissions[ADDRESS_ALL][STRING_ALL]].active) {
            return _evaluateCondition(
                conditions[permissions[ADDRESS_ALL][STRING_ALL]],
                parameterType,
                uintParameter,
                addressParameter,
                stringParameter
            );
        }

        // fallback for when no relevant permissions are found
        return addressDefaultPermission;
    }

    /**
     * @dev verifies that all conditions are satisfied
     * @param condition struct containing the parameters of the condition
     * @param parameterType enum indicating the type of paramter we are using for comparison
     * @param uintParameter parameter of type uint256 used to check for permissions
     * @param addressParameter parameter of type address used to check for permissions
     * @param stringParameter parameter of type string used to check for permissions
     * @return _ boolean indicating if the conditions are satisfied
     */
    function _evaluateCondition(
        Condition memory condition,
        ParameterType parameterType,
        uint256 uintParameter,
        address addressParameter,
        string memory stringParameter
    )
        internal
        view
        returns (bool)
    {
        if (condition.falseKey) return false;

        if (condition.trueKey) return true;

        if (condition.timestampBefore > 0 && condition.timestampBefore < block.timestamp) return false;

        if (condition.timestampAfter > 0 && condition.timestampAfter > block.timestamp) return false;

        if (parameterType == ParameterType.UintParam && condition.uintParameter != 0 && condition.uintParameter != uintParameter) {
            return false;
        } else if (parameterType == ParameterType.AddressParam && condition.addressParameter != address(0) && condition.addressParameter != addressParameter) {
            return false;
        } else if (parameterType == ParameterType.StringParam && keccak256(abi.encodePacked(condition.stringParameter)) != keccak256(abi.encodePacked("")) && keccak256(abi.encodePacked(condition.stringParameter)) != keccak256(abi.encodePacked(stringParameter))) { // solidity does not support comparing strings so we compare the hashes instead
            return false;
        }

        return true;
    }
}