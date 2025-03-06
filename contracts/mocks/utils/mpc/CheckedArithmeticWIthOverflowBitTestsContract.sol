// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract CheckedArithmeticWithOverflowBitTestsContract {

    struct AllGTCastingValues {
        gtUint8 a8_s;
        gtUint8 b8_s;
        gtUint16 a16_s;
        gtUint16 b16_s;
        gtUint32 a32_s;
        gtUint32 b32_s;
        gtUint64 a64_s;
        gtUint64 b64_s;
    }

    struct Check16 {
        gtUint16 res16_16;
        gtUint16 res8_16;
        gtUint16 res16_8;
    }

    struct Check32 {
        gtUint32 res32_32;
        gtUint32 res8_32;
        gtUint32 res32_8;
        gtUint32 res16_32;
        gtUint32 res32_16;
    }

    struct Check64 {
        gtUint64 res64_64;
        gtUint64 res8_64;
        gtUint64 res64_8;
        gtUint64 res16_64;
        gtUint64 res64_16;
        gtUint64 res32_64;
        gtUint64 res64_32;
    }

    uint8 addResult;
    uint8 subResult;
    uint8 mulResult;

    function getAddResult() public view returns (uint8) {
        return addResult;
    }

    function getSubResult() public view returns (uint8) {
        return subResult;
    }

    function getMulResult() public view returns (uint8) {
        return mulResult;
    }

    function setPublicValues(AllGTCastingValues memory castingValues, uint8 a, uint8 b) public{
        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);
        castingValues.a16_s =  MpcCore.setPublic16(a);
        castingValues.b16_s =  MpcCore.setPublic16(b);
        castingValues.a32_s =  MpcCore.setPublic32(a);
        castingValues.b32_s =  MpcCore.setPublic32(b);
        castingValues.a64_s =  MpcCore.setPublic64(a);
        castingValues.b64_s =  MpcCore.setPublic64(b);
    }

    function decryptAndCompareResults16(Check16 memory check16) public returns (uint16){

        // Calculate the result
        uint16 result = MpcCore.decrypt(check16.res16_16);

        require(result == MpcCore.decrypt(check16.res8_16) && result == MpcCore.decrypt(check16.res16_8),
            "decryptAndCompareAllResults: Failed to decrypt and compare all results");
        return result;
    }

    function decryptAndCompareResults32(Check32 memory check32) public returns (uint32){

        // Calculate the result
        uint32 result = MpcCore.decrypt(check32.res32_32);

        require(result == MpcCore.decrypt(check32.res8_32) && result == MpcCore.decrypt(check32.res32_8)
        && result == MpcCore.decrypt(check32.res32_16) && result == MpcCore.decrypt(check32.res16_32),
            "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function decryptAndCompareResults64(Check64 memory check64) public returns (uint64){

        // Calculate the result
        uint64 result = MpcCore.decrypt(check64.res64_64);

        require(result == MpcCore.decrypt(check64.res8_64) && result == MpcCore.decrypt(check64.res64_8)
        && result == MpcCore.decrypt(check64.res64_16) && result == MpcCore.decrypt(check64.res16_64)
        && result == MpcCore.decrypt(check64.res64_32) && result == MpcCore.decrypt(check64.res32_64),
            "decryptAndCompareAllResults: Failed to decrypt and compare all results");

        return result;
    }

    function checkedAddWithOverflowBitTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);

        // Calculate the expected result
        (gtBool overflow, gtUint8 gtResult) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b8_s);
        uint8 result = MpcCore.decrypt(gtResult);
        addResult = result;

        // Calculate the results with casting to 16
        (, check16.res16_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b16_s);
        (, check16.res8_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b16_s);
        (, check16.res16_8) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "addTest: cast 16 failed");

        // Calculate the result with casting to 32
        (, check32.res32_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b32_s);
        (, check32.res8_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b32_s);
        (, check32.res32_8) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b8_s);
        (, check32.res16_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b32_s);
        (, check32.res32_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "addTest: cast 32 failed");

        // Calculate the result with casting to 64
        (, check64.res64_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b64_s);
        (, check64.res8_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, castingValues.b64_s);
        (, check64.res64_8) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b8_s);
        (, check64.res16_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, castingValues.b64_s);
        (, check64.res64_16) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b16_s);
        (, check64.res32_64) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, castingValues.b64_s);
        (, check64.res64_32) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "addTest: cast 64 failed");

        // Check the result with scalar
        {
            (, gtUint8 gtResult8_1) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b8_s);
            (, gtUint8 gtResult8_2) = MpcCore.checkedAddWithOverflowBit(castingValues.a8_s, b);
            require(result == MpcCore.decrypt(gtResult8_1) && result == MpcCore.decrypt(gtResult8_2),
                "addTest: test 8 bits with scalar failed");
        }
        {

            (, gtUint16 gtResult16_1) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b16_s);
            (, gtUint16 gtResult16_2) = MpcCore.checkedAddWithOverflowBit(castingValues.a16_s, b);
            require(result == MpcCore.decrypt(gtResult16_1) && result == MpcCore.decrypt(gtResult16_2),
                "addTest: test 16 bits with scalar failed");
        }
        {
            (, gtUint32 gtResult32_1) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b32_s);
            (, gtUint32 gtResult32_2) = MpcCore.checkedAddWithOverflowBit(castingValues.a32_s, b);
            require(result == MpcCore.decrypt(gtResult32_1) && result == MpcCore.decrypt(gtResult32_2),
                "addTest: test 32 bits with scalar failed");
        }
        {
            (, gtUint64 gtResult64_1) = MpcCore.checkedAddWithOverflowBit(a, castingValues.b64_s);
            (, gtUint64 gtResult64_2) = MpcCore.checkedAddWithOverflowBit(castingValues.a64_s, b);
            require(result == MpcCore.decrypt(gtResult64_1) && result == MpcCore.decrypt(gtResult64_2),
                "addTest: test 64 bits with scalar failed");
        }

        return result;
    }

    function checkedSubWithOverflowBitTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);

        // Calculate the expected result
        (gtBool overflow, gtUint8 gtResult) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b8_s);
        uint8 result = MpcCore.decrypt(gtResult);
        subResult = result;

        // Calculate the results with casting to 16
        (, check16.res16_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b16_s);
        (, check16.res8_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b16_s);
        (, check16.res16_8) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(res16 == result, "subTest: cast 16 failed");

        // Calculate the result with casting to 32
        (, check32.res32_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b32_s);
        (, check32.res8_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b32_s);
        (, check32.res32_8) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b8_s);
        (, check32.res16_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b32_s);
        (, check32.res32_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "subTest: cast 32 failed");

        // Calculate the result with casting to 64
        (, check64.res64_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b64_s);
        (, check64.res8_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, castingValues.b64_s);
        (, check64.res64_8) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b8_s);
        (, check64.res16_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, castingValues.b64_s);
        (, check64.res64_16) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b16_s);
        (, check64.res32_64) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, castingValues.b64_s);
        (, check64.res64_32) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "subTest: cast 64 failed");

        // Check the result with scalar
        {
            (, gtUint8 gtResult8_1) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b8_s);
            (, gtUint8 gtResult8_2) = MpcCore.checkedSubWithOverflowBit(castingValues.a8_s, b);
            require(result == MpcCore.decrypt(gtResult8_1) && result == MpcCore.decrypt(gtResult8_2),
                "subTest: test 8 bits with scalar failed");
        }
        {
            (, gtUint16 gtResult16_1) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b16_s);
            (, gtUint16 gtResult16_2) = MpcCore.checkedSubWithOverflowBit(castingValues.a16_s, b);
            require(result == MpcCore.decrypt(gtResult16_1) && result == MpcCore.decrypt(gtResult16_2),
                "subTest: test 16 bits with scalar failed");
        }
        {
            (, gtUint32 gtResult32_1) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b32_s);
            (, gtUint32 gtResult32_2) = MpcCore.checkedSubWithOverflowBit(castingValues.a32_s, b);
            require(result == MpcCore.decrypt(gtResult32_1) && result == MpcCore.decrypt(gtResult32_2),
                "subTest: test 32 bits with scalar failed");
        }
        {
            (, gtUint64 gtResult64_1) = MpcCore.checkedSubWithOverflowBit(a, castingValues.b64_s);
            (, gtUint64 gtResult64_2) = MpcCore.checkedSubWithOverflowBit(castingValues.a64_s, b);
            require(result == MpcCore.decrypt(gtResult64_1) && result == MpcCore.decrypt(gtResult64_2),
                "subTest: test 64 bits with scalar failed");
        }

        return result;
    }

    function checkedMulWithOverflowBitTest(uint8 a, uint8 b) public returns (uint8) {
        AllGTCastingValues memory castingValues;
        Check16 memory check16;
        Check32 memory check32;
        Check64 memory check64;
        setPublicValues(castingValues, a, b);

        // Calculate the expected result
        (gtBool overflow, gtUint8 gtResult) = MpcCore.checkedMulWithOverflowBit(castingValues.a8_s, castingValues.b8_s);
        uint8 result = MpcCore.decrypt(gtResult);
        mulResult = result;

        // Calculate the results with casting to 16
        (, check16.res16_16) = MpcCore.checkedMulWithOverflowBit(castingValues.a16_s, castingValues.b16_s);
        (, check16.res8_16) = MpcCore.checkedMulWithOverflowBit(castingValues.a8_s, castingValues.b16_s);
        (, check16.res16_8) = MpcCore.checkedMulWithOverflowBit(castingValues.a16_s, castingValues.b8_s);
        uint16 res16 = decryptAndCompareResults16(check16);
        require(result == res16, "mulTest: cast 16 failed");

        // Calculate the result with casting to 32
        (, check32.res32_32) = MpcCore.checkedMulWithOverflowBit(castingValues.a32_s, castingValues.b32_s);
        (, check32.res8_32) = MpcCore.checkedMulWithOverflowBit(castingValues.a8_s, castingValues.b32_s);
        (, check32.res32_8) = MpcCore.checkedMulWithOverflowBit(castingValues.a32_s, castingValues.b8_s);
        (, check32.res16_32) = MpcCore.checkedMulWithOverflowBit(castingValues.a16_s, castingValues.b32_s);
        (, check32.res32_16) = MpcCore.checkedMulWithOverflowBit(castingValues.a32_s, castingValues.b16_s);
        uint32 res32 = decryptAndCompareResults32(check32);
        require(result == res32, "mulTest: cast 32 failed");

        // Calculate the result with casting to 64
        (, check64.res64_64) = MpcCore.checkedMulWithOverflowBit(castingValues.a64_s, castingValues.b64_s);
        (, check64.res8_64) = MpcCore.checkedMulWithOverflowBit(castingValues.a8_s, castingValues.b64_s);
        (, check64.res64_8) = MpcCore.checkedMulWithOverflowBit(castingValues.a64_s, castingValues.b8_s);
        (, check64.res16_64) = MpcCore.checkedMulWithOverflowBit(castingValues.a16_s, castingValues.b64_s);
        (, check64.res64_16) = MpcCore.checkedMulWithOverflowBit(castingValues.a64_s, castingValues.b16_s);
        (, check64.res32_64) = MpcCore.checkedMulWithOverflowBit(castingValues.a32_s, castingValues.b64_s);
        (, check64.res64_32) = MpcCore.checkedMulWithOverflowBit(castingValues.a64_s, castingValues.b32_s);
        uint64 res64 = decryptAndCompareResults64(check64);
        require(result == res64, "mulTest: cast 64 failed");

        // Check the result with scalar
        {
            (, gtUint8 gtResult8_1) = MpcCore.checkedMulWithOverflowBit(a, castingValues.b8_s);
            (, gtUint8 gtResult8_2) = MpcCore.checkedMulWithOverflowBit(castingValues.a8_s, b);
            require(result == MpcCore.decrypt(gtResult8_1) && result == MpcCore.decrypt(gtResult8_2),
                "mulTest: test 8 bits with scalar failed");
        }
        {
            (, gtUint16 gtResult16_1) = MpcCore.checkedMulWithOverflowBit(a, castingValues.b16_s);
            (, gtUint16 gtResult16_2) = MpcCore.checkedMulWithOverflowBit(castingValues.a16_s, b);
            require(result == MpcCore.decrypt(gtResult16_1) && result == MpcCore.decrypt(gtResult16_2),
                "mulTest: test 16 bits with scalar failed");
        }
        {
            (, gtUint32 gtResult32_1) = MpcCore.checkedMulWithOverflowBit(a, castingValues.b32_s);
            (, gtUint32 gtResult32_2) = MpcCore.checkedMulWithOverflowBit(castingValues.a32_s, b);
            require(result == MpcCore.decrypt(gtResult32_1) && result == MpcCore.decrypt(gtResult32_2),
                "mulTest: test 32 bits with scalar failed");
        }
        {
            (, gtUint64 gtResult64_1) = MpcCore.checkedMulWithOverflowBit(a, castingValues.b64_s);
            (, gtUint64 gtResult64_2) = MpcCore.checkedMulWithOverflowBit(castingValues.a64_s, b);
            require(result == MpcCore.decrypt(gtResult64_1) && result == MpcCore.decrypt(gtResult64_2),
                "mulTest: test 64 bits with scalar failed");
        }

        return result;
    }
}