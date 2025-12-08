// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract OnBoard256TestsContract {
    uint256 onboardOffboardResult;
    ctUint256 storedCiphertext;

    function getOnboardOffboardResult() public view returns (uint256) {
        return onboardOffboardResult;
    }

    function getStoredCiphertext() public view returns (ctUint256 memory) {
        return storedCiphertext;
    }

    /**
     * @dev Test the round-trip: setPublic -> offBoard -> onBoard -> decrypt
     * @param value The value to test
     */
    function testOnBoardOffBoardRoundTrip(uint256 value) public returns (uint256) {
        // Step 1: Create garbled text from public value
        gtUint256 gtValue = MpcCore.setPublic256(value);
        
        // Step 2: Convert garbled text to ciphertext (offBoard)
        ctUint256 memory ciphertext = MpcCore.offBoard(gtValue);
        storedCiphertext = ciphertext;
        
        // Step 3: Convert ciphertext back to garbled text (onBoard)
        gtUint256 gtValue2 = MpcCore.onBoard(ciphertext);
        
        // Step 4: Decrypt to verify the value
        uint256 result = MpcCore.decrypt(gtValue2);
        onboardOffboardResult = result;
        
        require(result == value, "OnBoard/OffBoard round-trip failed");
        
        return result;
    }

    /**
     * @dev Test onBoard with multiple values
     */
    function testOnBoardMultipleValues(uint256 a, uint256 b, uint256 c) public returns (uint256, uint256, uint256) {
        // Test value A
        gtUint256 gtA = MpcCore.setPublic256(a);
        ctUint256 memory ctA = MpcCore.offBoard(gtA);
        gtUint256 gtA2 = MpcCore.onBoard(ctA);
        uint256 resultA = MpcCore.decrypt(gtA2);
        require(resultA == a, "Value A test failed");
        
        // Test value B
        gtUint256 gtB = MpcCore.setPublic256(b);
        ctUint256 memory ctB = MpcCore.offBoard(gtB);
        gtUint256 gtB2 = MpcCore.onBoard(ctB);
        uint256 resultB = MpcCore.decrypt(gtB2);
        require(resultB == b, "Value B test failed");
        
        // Test value C
        gtUint256 gtC = MpcCore.setPublic256(c);
        ctUint256 memory ctC = MpcCore.offBoard(gtC);
        gtUint256 gtC2 = MpcCore.onBoard(ctC);
        uint256 resultC = MpcCore.decrypt(gtC2);
        require(resultC == c, "Value C test failed");
        
        return (resultA, resultB, resultC);
    }

    /**
     * @dev Test onBoard with edge cases (0 and max)
     */
    function testOnBoardEdgeCases() public returns (uint256, uint256) {
        // Test zero
        uint256 zero = 0;
        gtUint256 gtZero = MpcCore.setPublic256(zero);
        ctUint256 memory ctZero = MpcCore.offBoard(gtZero);
        gtUint256 gtZero2 = MpcCore.onBoard(ctZero);
        uint256 resultZero = MpcCore.decrypt(gtZero2);
        require(resultZero == zero, "Zero test failed");
        
        // Test max
        uint256 max = type(uint256).max;
        gtUint256 gtMax = MpcCore.setPublic256(max);
        ctUint256 memory ctMax = MpcCore.offBoard(gtMax);
        gtUint256 gtMax2 = MpcCore.onBoard(ctMax);
        uint256 resultMax = MpcCore.decrypt(gtMax2);
        require(resultMax == max, "Max test failed");
        
        return (resultZero, resultMax);
    }

    /**
     * @dev Test onBoard with values that cross 128-bit boundary
     */
    function testOnBoard128BitBoundary() public returns (uint256, uint256) {
        // Test value below 128-bit boundary (2^127 - 1)
        uint256 below128 = (uint256(1) << 127) - 1;
        gtUint256 gtBelow = MpcCore.setPublic256(below128);
        ctUint256 memory ctBelow = MpcCore.offBoard(gtBelow);
        gtUint256 gtBelow2 = MpcCore.onBoard(ctBelow);
        uint256 resultBelow = MpcCore.decrypt(gtBelow2);
        require(resultBelow == below128, "Below 128-bit test failed");
        
        // Test value above 128-bit boundary (2^128)
        uint256 above128 = uint256(1) << 128;
        gtUint256 gtAbove = MpcCore.setPublic256(above128);
        ctUint256 memory ctAbove = MpcCore.offBoard(gtAbove);
        gtUint256 gtAbove2 = MpcCore.onBoard(ctAbove);
        uint256 resultAbove = MpcCore.decrypt(gtAbove2);
        require(resultAbove == above128, "Above 128-bit test failed");
        
        return (resultBelow, resultAbove);
    }
}

