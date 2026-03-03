// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract OnBoard128TestsContract {
    uint128 onboardOffboardResult;
    ctUint128 storedCiphertext;

    function getOnboardOffboardResult() public view returns (uint128) {
        return onboardOffboardResult;
    }

    function getStoredCiphertext() public view returns (ctUint128) {
        return storedCiphertext;
    }

    /**
     * @dev Test the round-trip: setPublic -> offBoard -> onBoard -> decrypt
     * @param value The value to test
     */
    function testOnBoardOffBoardRoundTrip(uint128 value) public returns (uint128) {
        // Step 1: Create garbled text from public value
        gtUint128 gtValue = MpcCore.setPublic128(value);
        
        // Step 2: Convert garbled text to ciphertext (offBoard)
        ctUint128 ciphertext = MpcCore.offBoard(gtValue);
        storedCiphertext = ciphertext;
        
        // Step 3: Convert ciphertext back to garbled text (onBoard)
        gtUint128 gtValue2 = MpcCore.onBoard(ciphertext);
        
        // Step 4: Decrypt to verify the value
        uint128 result = MpcCore.decrypt(gtValue2);
        onboardOffboardResult = result;
        
        require(result == value, "OnBoard/OffBoard round-trip failed");
        
        return result;
    }

    /**
     * @dev Test onBoard with multiple values
     */
    function testOnBoardMultipleValues(uint128 a, uint128 b, uint128 c) public returns (uint128, uint128, uint128) {
        // Test value A
        gtUint128 gtA = MpcCore.setPublic128(a);
        ctUint128 ctA = MpcCore.offBoard(gtA);
        gtUint128 gtA2 = MpcCore.onBoard(ctA);
        uint128 resultA = MpcCore.decrypt(gtA2);
        require(resultA == a, "Value A test failed");
        
        // Test value B
        gtUint128 gtB = MpcCore.setPublic128(b);
        ctUint128 ctB = MpcCore.offBoard(gtB);
        gtUint128 gtB2 = MpcCore.onBoard(ctB);
        uint128 resultB = MpcCore.decrypt(gtB2);
        require(resultB == b, "Value B test failed");
        
        // Test value C
        gtUint128 gtC = MpcCore.setPublic128(c);
        ctUint128 ctC = MpcCore.offBoard(gtC);
        gtUint128 gtC2 = MpcCore.onBoard(ctC);
        uint128 resultC = MpcCore.decrypt(gtC2);
        require(resultC == c, "Value C test failed");
        
        return (resultA, resultB, resultC);
    }

    /**
     * @dev Test onBoard with edge cases (0 and max)
     */
    function testOnBoardEdgeCases() public returns (uint128, uint128) {
        // Test zero
        uint128 zero = 0;
        gtUint128 gtZero = MpcCore.setPublic128(zero);
        ctUint128 ctZero = MpcCore.offBoard(gtZero);
        gtUint128 gtZero2 = MpcCore.onBoard(ctZero);
        uint128 resultZero = MpcCore.decrypt(gtZero2);
        require(resultZero == zero, "Zero test failed");
        
        // Test max
        uint128 max = type(uint128).max;
        gtUint128 gtMax = MpcCore.setPublic128(max);
        ctUint128 ctMax = MpcCore.offBoard(gtMax);
        gtUint128 gtMax2 = MpcCore.onBoard(ctMax);
        uint128 resultMax = MpcCore.decrypt(gtMax2);
        require(resultMax == max, "Max test failed");
        
        return (resultZero, resultMax);
    }
}

