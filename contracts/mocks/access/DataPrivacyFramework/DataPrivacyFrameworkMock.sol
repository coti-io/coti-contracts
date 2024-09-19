// SPDX-License-Identifier: MIT
// Data Privacy Framework (last updated v0.1.0)

pragma solidity ^0.8.19;

import "../../../access/DataPrivacyFramework/DataPrivacyFramework.sol";

contract DataPrivacyFrameworkMock is DataPrivacyFramework {
    constructor() DataPrivacyFramework(true, true) {}
}