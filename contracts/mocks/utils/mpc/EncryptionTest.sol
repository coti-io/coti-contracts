// SPDX-License-Identifier: SYMM-Core-Business-Source-License-1.1
// This contract is licensed under the SYMM Core Business Source License 1.1
// Copyright (c) 2023 Symmetry Labs AG
// For more information, see https://docs.symm.io/legal-disclaimer/license
pragma solidity >=0.8.18;

import "../../../utils/mpc/MpcCore.sol";

interface IEncryptionTestEvents {
    event TestEncryptionEvent(
        address user,
        ctUint256 encryptedValue,
        uint256 originalValue,
        uint256 storageValue
    );
}

contract EncryptionTest is IEncryptionTestEvents {
    using MpcCore for gtUint256;
    using MpcCore for gtInt256;
    using MpcCore for gtBool;
    
    // Storage to track values - using simple mapping
    mapping(address => utUint256) public storedValues;
    mapping(address => utUint256) public storedQuantities; // Separate storage for quantity
    
    // Simple mapping for encryption addresses (normally from LibAccount)
    mapping(address => address) public userEncryptionAddresses;
    
    /**
     * @notice Sets the encryption address for a user (simulates LibAccount.getUserEncryptionAddress)
     * @param user The user address
     * @param encryptionAddress The encryption address to use
     */
    function setEncryptionAddress(address user, address encryptionAddress) external {
        userEncryptionAddresses[user] = encryptionAddress;
    }
    
    /**
     * @notice Gets the encryption address for a user (defaults to user address if not set)
     */
    function getUserEncryptionAddress(address user) internal view returns (address) {
        address encAddr = userEncryptionAddresses[user];
        return encAddr != address(0) ? encAddr : user;
    }
    
    /**
     * @notice Safe onboard helper (simulates LockedValuesOps.safeOnboard)
     */
    function safeOnboard(ctUint256 memory value) internal returns (gtUint256) {
        if (ctUint128.unwrap(value.ciphertextHigh) == uint256(0) && ctUint128.unwrap(value.ciphertextLow) == uint256(0)) {
            return MpcCore.setPublic256(uint256(0));
        }
        return MpcCore.onBoard(value);
    }
    
    /**
     * @notice Test function that mimics the exact sendQuote pattern with multiple values
     * This simulates the issue: validate -> use in operations -> store -> then offboard for events
     * The key issue: gtPrice and gtQuantity are used AFTER many MPC operations that might corrupt garbled table state
     * @param encryptedPrice The encrypted price value
     * @param encryptedQuantity The encrypted quantity value
     * @param originalPrice The original plaintext price
     * @param originalQuantity The original plaintext quantity
     */
    function testMultipleEncryptionFlow(
        itUint256 memory encryptedPrice,
        itUint256 memory encryptedQuantity,
        uint256 originalPrice,
        uint256 originalQuantity
    ) external {
        // Step 1: Validate both ciphertexts (like sendQuote line 26-27)
        gtUint256 gtPrice = MpcCore.validateCiphertext(encryptedPrice);
        gtUint256 gtQuantity = MpcCore.validateCiphertext(encryptedQuantity);
        gtUint256 gtCva = MpcCore.setPublic256(originalPrice / 10); // Simulate CVA
        gtUint256 gtLf = MpcCore.setPublic256(originalPrice / 20); // Simulate LF
        gtUint256 gtPartyAmm = MpcCore.setPublic256(originalPrice / 30);
        gtUint256 gtPartyBmm = MpcCore.setPublic256(originalPrice / 40);
        
        address userEncryptionAddress = getUserEncryptionAddress(msg.sender);
        
        // Step 2: Simulate ALL the MPC operations from PartyAFacetImpl.sendQuote
        // This is the CRITICAL part - these operations might corrupt the garbled table
        
        // Simulate mux operation (line 68-72)
        gtUint256 gtTradingPrice = MpcCore.mux(
            MpcCore.eq(MpcCore.setPublic256(uint256(0)), MpcCore.setPublic256(uint256(0))), // Always true for LIMIT
            gtPrice,
            MpcCore.setPublic256(originalPrice)
        );
        
        // Simulate totalForPartyA calculation (line 75) - simplified version
        gtUint256 gtTotalForPartyA = gtCva.add(gtLf).add(gtPartyAmm).add(gtPartyBmm);
        
        // Simulate minLfRequired calculation (line 77-79)
        gtUint256 minLfRequired = gtTotalForPartyA.mul(MpcCore.setPublic256(uint256(1e17))).div(MpcCore.setPublic256(uint256(1e18)));
        gtBool lfSufficient = gtLf.ge(minLfRequired);
        
        // Simulate quoteSufficient check (line 83)
        gtBool quoteSufficient = gtTotalForPartyA.ge(MpcCore.setPublic256(uint256(1000)));
        
        // Simulate trading fee calculation (line 86-88) - THIS USES gtQuantity and gtPrice
        gtUint256 gtTradingFee = gtQuantity.mul(gtTradingPrice).mul(MpcCore.setPublic256(uint256(1e15))).div(MpcCore.setPublic256(uint256(1e36)));
        
        // Simulate totalRequired (line 91)
        gtUint256 totalRequired = gtTotalForPartyA.add(gtTradingFee);
        
        // Simulate balance check (line 94-95)
        // Make balance large enough to always pass - use a value much larger than totalRequired
        // Calculate a safe balance: totalRequired * 10 to ensure it's always sufficient
        gtUint256 gtSafeBalance = totalRequired.mul(MpcCore.setPublic256(uint256(10)));
        gtInt256 gtAvailableBalance = gtSafeBalance.toSigned();
        gtBool balanceSufficient = totalRequired.toSigned().le(gtAvailableBalance);
        
        // Combine validations (line 98)
        gtBool allValidationsPassed = lfSufficient.and(quoteSufficient).and(balanceSufficient);
        require(MpcCore.decrypt(allValidationsPassed), "Validation failed");
        
        // Step 3: Simulate more MPC operations that might affect garbled table
        // Simulate pending locked balances update pattern (onBoard -> add -> offBoard)
        utUint256 storage storagePending = storedValues[msg.sender];
        gtUint256 gtPending = safeOnboard(storagePending.ciphertext);
        gtUint256 gtNewPending = gtPending.add(gtCva).add(gtLf).add(gtPartyAmm).add(gtPartyBmm);
        storedValues[msg.sender] = MpcCore.offBoardCombined(gtNewPending, userEncryptionAddress);
        
        // Step 4: Store values using offBoardCombined (like line 132-134 in PartyAFacetImpl)
        // CRITICAL: This is where gtPrice and gtQuantity are used with offBoardCombined
        // After this, the garbled table state might be corrupted, but we'll try to reuse them later
        // This simulates storing the quote in PartyAFacetImpl.sendQuote lines 132-134
        storedValues[msg.sender] = MpcCore.offBoardCombined(gtPrice, userEncryptionAddress);
        storedQuantities[msg.sender] = MpcCore.offBoardCombined(gtQuantity, userEncryptionAddress);
        
        // Step 5: Simulate trading fee deduction pattern (line 163-166)
        // Simulate balance operations
        utUint256 storage storageBalance = storedValues[msg.sender];
        gtUint256 gtCurrentBalance = safeOnboard(storageBalance.ciphertext);
        uint256 fee = MpcCore.decrypt(gtTradingFee);
        gtUint256 gtFeeAmount = MpcCore.setPublic256(fee);
        gtUint256 gtNewBalance = gtCurrentBalance.sub(gtFeeAmount);
        storedValues[msg.sender] = MpcCore.offBoardCombined(gtNewBalance, userEncryptionAddress);
        
        // Step 6: Do MORE operations that might corrupt garbled table state
        // Simulate additional MPC operations that happen in sendQuote
        for (uint256 i = 0; i < 10; i++) {
            gtUint256 temp = gtQuantity.mul(MpcCore.setPublic256(uint256(i + 1)));
            gtBool check = temp.ge(gtQuantity);
            MpcCore.decrypt(check); // This might affect garbled table state
        }
        
        // Step 7: NOW try to offboard the ORIGINAL gtPrice and gtQuantity for events
        // THIS IS WHERE THE BUG HAPPENS - after all the operations above, the garbled table
        // state might be corrupted, so offBoardToUser might produce wrong ciphertexts
        address partyAEncryptionAddress = getUserEncryptionAddress(msg.sender);
        ctUint256 memory ctPrice = MpcCore.offBoardToUser(gtPrice, partyAEncryptionAddress);
        ctUint256 memory ctQuantity = MpcCore.offBoardToUser(gtQuantity, partyAEncryptionAddress);
        
        // Get stored value for comparison
        gtUint256 gtStoredPrice = safeOnboard(storedValues[msg.sender].ciphertext);
        uint256 storagePrice = MpcCore.decrypt(gtStoredPrice);
        
        emit TestEncryptionEvent(
            msg.sender,
            ctPrice,
            originalPrice,
            storagePrice
        );
        
        emit TestEncryptionEvent(
            msg.sender,
            ctQuantity,
            originalQuantity,
            storagePrice
        );
    }
}

