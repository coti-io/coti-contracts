// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../access/DataPrivacyFramework/DataPrivacyFramework.sol";

contract DataPrivacyFrameworkMock is DataPrivacyFramework {
    constructor() DataPrivacyFramework(true, true) {}
}