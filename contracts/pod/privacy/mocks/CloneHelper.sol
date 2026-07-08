// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/Clones.sol";

/// @dev Test helper to deploy minimal clones of portal/pToken implementations.
contract CloneHelper {
    address public lastClone;

    function clone(address implementation) external returns (address cloned) {
        cloned = Clones.clone(implementation);
        lastClone = cloned;
    }
}
