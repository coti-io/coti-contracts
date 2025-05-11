// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

type gtBool is uint256;
type gtUint8 is uint256;
type gtUint16 is uint256;
type gtUint32 is uint256;
type gtUint64 is uint256;

// we use a struct because user-defined value types can only be elementary value types
struct gtUint128 {
    gtUint64 high;
    gtUint64 low;
}

// we use a struct because user-defined value types can only be elementary value types
struct gtUint256 {
    gtUint128 high;
    gtUint128 low;
}

// we use a struct because user-defined value types can only be elementary value types
// 8 characters (in byte form) per cell and the final cell padded with zeroes if needed
struct gtString {
    gtUint64[] value;
}

type ctBool is uint256;
type ctUint8 is uint256;
type ctUint16 is uint256;
type ctUint32 is uint256;
type ctUint64 is uint256;

// we use a struct because user-defined value types can only be elementary value types
struct ctUint128 {
    ctUint64 high;
    ctUint64 low;
}

// we use a struct because user-defined value types can only be elementary value types
struct ctUint256 {
    ctUint128 high;
    ctUint128 low;
}

// we use a struct because user-defined value types can only be elementary value types
// 8 characters (in byte form) per cell and the final cell padded with zeroes if needed
struct ctString {
    ctUint64[] value;
}

struct itBool {
    ctBool ciphertext;
    bytes signature;
}
struct itUint8 {
    ctUint8 ciphertext;
    bytes signature;
}
struct itUint16 {
    ctUint16 ciphertext;
    bytes signature;
}
struct itUint32 {
    ctUint32 ciphertext;
    bytes signature;
}
struct itUint64 {
    ctUint64 ciphertext;
    bytes signature;
}
struct itUint128 {
    ctUint128 ciphertext;
    bytes[2] signature;
}
struct itUint256 {
    ctUint256 ciphertext;
    bytes[2][2] signature;
}
struct itString {
    ctString ciphertext;
    bytes[] signature;
}

struct utBool {
    ctBool ciphertext;
    ctBool userCiphertext;
}
struct utUint8 {
    ctUint8 ciphertext;
    ctUint8 userCiphertext;
}
struct utUint16 {
    ctUint16 ciphertext;
    ctUint16 userCiphertext;
}
struct utUint32 {
    ctUint32 ciphertext;
    ctUint32 userCiphertext;
}
struct utUint64 {
    ctUint64 ciphertext;
    ctUint64 userCiphertext;
}
struct utUint128 {
    ctUint128 ciphertext;
    ctUint128 userCiphertext;
}
struct utUint256 {
    ctUint256 ciphertext;
    ctUint256 userCiphertext;
}
struct utString {
    ctString ciphertext;
    ctString userCiphertext;
}


import "./MpcInterface.sol";


library MpcCore {

    enum MPC_TYPE {SBOOL_T , SUINT8_T , SUINT16_T, SUINT32_T ,SUINT64_T }
    enum ARGS {BOTH_SECRET , LHS_PUBLIC, RHS_PUBLIC  }
    uint public constant RSA_SIZE = 256;

    function combineEnumsToBytes2(MPC_TYPE mpcType, ARGS argsType) internal pure returns (bytes2) {
        return bytes2(uint16(mpcType) << 8 | uint8(argsType));
    }

    function combineEnumsToBytes3(MPC_TYPE mpcType1, MPC_TYPE mpcType2, ARGS argsType) internal pure returns (bytes3) {
        return bytes3(uint24(mpcType1) << 16 | uint16(mpcType2) << 8 | uint8(argsType));
    }

    function combineEnumsToBytes4(MPC_TYPE mpcType1, MPC_TYPE mpcType2, MPC_TYPE mpcType3, ARGS argsType) internal pure returns (bytes4) {
        return bytes4(uint32(mpcType1) << 24 | uint24(mpcType2) << 16 | uint16(mpcType3) << 8 | uint8(argsType));
    }

    function combineEnumsToBytes5(MPC_TYPE mpcType1, MPC_TYPE mpcType2, MPC_TYPE mpcType3, MPC_TYPE mpcType4, ARGS argsType) internal pure returns (bytes5) {
        return bytes5(uint40(mpcType1) << 32 | uint32(mpcType2) << 24 | uint24(mpcType3) << 16 | uint16(mpcType4) << 8 | uint8(argsType));
    }

    function checkOverflow(gtBool bit) private {
        // To revert on overflow, the require statement must fail when the overflow bit is set.
        // Naturally, we would check that the overflow bit is 0.
        // However, directly requiring the bit to be 0 causes gas estimation to fail, as it always returns 1.
        // To handle this, we apply a NOT operation to the bit and require the result to be 1.
        //
        // Summary of all cases:
        //  1. **Overflow scenario**: The overflow bit is 1 → NOT operation returns 0 → require fails → transaction reverts.
        //  2. **No overflow**: The overflow bit is 0 → NOT operation returns 1 → require passes → transaction proceeds.
        //  3. **Gas estimation**: Decrypt always returns 1 during gas estimation → require passes → no impact on actual execution.
        gtBool notBit = not(bit);
        // revert on overflow
        require(decrypt(notBit) == true, "overflow error");
    }

    function checkRes8(gtBool bit, gtUint8 res) private returns (gtUint8) {
        // revert on overflow
        checkOverflow(bit);

        // return the output if there is no overflow
        return res;
    }

    function checkRes16(gtBool bit, gtUint16 res) private returns (gtUint16) {
        // revert on overflow
        checkOverflow(bit);

        // return the output if there is no overflow
        return res;
    }

    function checkRes32(gtBool bit, gtUint32 res) private returns (gtUint32) {
        // revert on overflow
        checkOverflow(bit);

        // return the output if there is no overflow
        return res;
    }

    function checkRes64(gtBool bit, gtUint64 res) private returns (gtUint64) {
        // revert on overflow
        checkOverflow(bit);

        // return the output if there is no overflow
        return res;
    }

    function getUserKey(bytes calldata signedEK, bytes calldata signature) internal returns (bytes memory keyShare0, bytes memory keyShare1) {
        bytes memory combined = new bytes(signature.length + signedEK.length);

        // Copy contents of signature into combined
        for (uint i = 0; i < signature.length; i++) {
            combined[i] = signature[i];
        }

        // Copy contents of _bytes2 into combined after _bytes1
        for (uint j = 0; j < signedEK.length; j++) {
            combined[signature.length + j] = signedEK[j];
        }
        bytes memory bothKeys = ExtendedOperations(address(MPC_PRECOMPILE)).GetUserKey(combined);
        bytes memory share0 = new bytes(RSA_SIZE);
        bytes memory share1 = new bytes(RSA_SIZE);

        // Copy the first key to the first share array
        for (uint i = 0; i < share0.length; i++) {
            share0[i] = bothKeys[i];
        }

        // Copy the second key to the second share array
        for (uint i = 0; i < share1.length; i++) {
            share1[i] = bothKeys[i + RSA_SIZE];
        }
        return (share0, share1);
    }



    // =========== 1 bit operations ==============

    function validateCiphertext(itBool memory input) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        ValidateCiphertext(bytes1(uint8(MPC_TYPE.SBOOL_T)), ctBool.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctBool ct) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OnBoard(bytes1(uint8(MPC_TYPE.SBOOL_T)), ctBool.unwrap(ct)));
    }

    function offBoard(gtBool pt) internal returns (ctBool) {
        return ctBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoard(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(pt)));
    }

    function offBoardToUser(gtBool pt, address addr) internal returns (ctBool) {
        return ctBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoardToUser(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtBool pt, address addr) internal returns (utBool memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic(bool pt) internal returns (gtBool) {
        uint256 temp;
        temp = pt ? 1 : 0;
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        SetPublic(bytes1(uint8(MPC_TYPE.SBOOL_T)), temp));
    }

    function rand() internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).Rand(bytes1(uint8(MPC_TYPE.SBOOL_T))));
    }

    function and(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        And(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function or(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Or(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function xor(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Xor(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function eq(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Eq(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function ne(gtBool a, gtBool b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ne(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function decrypt(gtBool ct) internal returns (bool){
        uint256 temp = ExtendedOperations(address(MPC_PRECOMPILE)).
            Decrypt(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(ct));
        return temp != 0;
    }

    function mux(gtBool bit, gtBool a, gtBool b) internal returns (gtBool){
        return  gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mux(combineEnumsToBytes3(MPC_TYPE.SBOOL_T, MPC_TYPE.SBOOL_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtBool.unwrap(a), gtBool.unwrap(b)));
    }

    function not(gtBool a) internal returns (gtBool){
        return  gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Not(bytes1(uint8(MPC_TYPE.SBOOL_T)), gtBool.unwrap(a)));
    }


    // =========== Operations with BOTH_SECRET parameter ===========
    // =========== 8 bit operations ==============

    function validateCiphertext(itUint8 memory input) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT8_T)), ctUint8.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint8 ct) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OnBoard(bytes1(uint8(MPC_TYPE.SUINT8_T)), ctUint8.unwrap(ct)));
    }

    function offBoard(gtUint8 pt) internal returns (ctUint8) {
        return ctUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoard(bytes1(uint8(MPC_TYPE.SUINT8_T)), gtUint8.unwrap(pt)));
    }

    function offBoardToUser(gtUint8 pt, address addr) internal returns (ctUint8) {
        return ctUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT8_T)), gtUint8.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint8 pt, address addr) internal returns (utUint8 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }
    function setPublic8(uint8 pt) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        SetPublic(bytes1(uint8(MPC_TYPE.SUINT8_T)), uint256(pt)));
    }

    function rand8() internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).Rand(bytes1(uint8(MPC_TYPE.SUINT8_T))));
    }

    function randBoundedBits8(uint8 numBits) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT8_T)), numBits));
    }

    function add(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedAdd(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint8 a, gtUint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function sub(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedSub(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint8 a, gtUint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function mul(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedMul(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b));
        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint8 a, gtUint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b));
        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function div(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function decrypt(gtUint8 ct) internal returns (uint8){
        return uint8(ExtendedOperations(address(MPC_PRECOMPILE)).
        Decrypt(bytes1(uint8(MPC_TYPE.SUINT8_T)), gtUint8.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint8 b) internal returns (gtUint8){
        return  gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint8 b, gtUint8 amount) internal returns (gtUint8, gtUint8, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint8.wrap(new_a), gtUint8.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint8 a, gtUint8 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint8, gtUint8, gtBool, gtUint8){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint8.wrap(new_a), gtUint8.wrap(new_b), gtBool.wrap(res), gtUint8.wrap(new_allowance));
    }


    // =========== 16 bit operations ==============

    function validateCiphertext(itUint16 memory input) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT16_T)), ctUint16.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint16 ct) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OnBoard(bytes1(uint8(MPC_TYPE.SUINT16_T)), ctUint16.unwrap(ct)));
    }

    function offBoard(gtUint16 pt) internal returns (ctUint16) {
        return ctUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoard(bytes1(uint8(MPC_TYPE.SUINT16_T)), gtUint16.unwrap(pt)));
    }

    function offBoardToUser(gtUint16 pt, address addr) internal returns (ctUint16) {
        return ctUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT16_T)), gtUint16.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint16 pt, address addr) internal returns (utUint16 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic16(uint16 pt) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        SetPublic(bytes1(uint8(MPC_TYPE.SUINT16_T)), uint256(pt)));
    }

    function rand16() internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).Rand(bytes1(uint8(MPC_TYPE.SUINT16_T))));
    }

    function randBoundedBits16(uint8 numBits) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT16_T)), numBits));
    }

    function add(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }
    
    function checkedAdd(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint16 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function sub(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedSub(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint16 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function mul(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedMul(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint16 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function div(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }
    function min(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function decrypt(gtUint16 ct) internal returns (uint16){
        return uint16(ExtendedOperations(address(MPC_PRECOMPILE)).
        Decrypt(bytes1(uint8(MPC_TYPE.SUINT16_T)), gtUint16.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint16 b) internal returns (gtUint16){
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint16.unwrap(b)));
    }

    function transfer(gtUint16 a, gtUint16 b, gtUint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint16 a, gtUint16 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }



    // =========== 32 bit operations ==============

    function validateCiphertext(itUint32 memory input) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT32_T)), ctUint32.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint32 ct) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OnBoard(bytes1(uint8(MPC_TYPE.SUINT32_T)), ctUint32.unwrap(ct)));
    }

    function offBoard(gtUint32 pt) internal returns (ctUint32) {
        return ctUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoard(bytes1(uint8(MPC_TYPE.SUINT32_T)), gtUint32.unwrap(pt)));
    }

    function offBoardToUser(gtUint32 pt, address addr) internal returns (ctUint32) {
        return ctUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT32_T)), gtUint32.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint32 pt, address addr) internal returns (utUint32 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic32(uint32 pt) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        SetPublic(bytes1(uint8(MPC_TYPE.SUINT32_T)), uint256(pt)));
    }

    function rand32() internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).Rand(bytes1(uint8(MPC_TYPE.SUINT32_T))));
    }

    function randBoundedBits32(uint8 numBits) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT32_T)), numBits));
    }

    function add(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function checkedAdd(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint32 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function sub(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function checkedSub(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint32 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function mul(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function checkedMul(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b));
        
        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint32 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function div(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function max(gtUint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function decrypt(gtUint32 ct) internal returns (uint32){
        return uint32(ExtendedOperations(address(MPC_PRECOMPILE)).
        Decrypt(bytes1(uint8(MPC_TYPE.SUINT32_T)), gtUint32.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint32 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint32.unwrap(b)));
    }

    function transfer(gtUint32 a, gtUint32 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }



    // =========== 64 bit operations ==============

    function validateCiphertext(itUint64 memory input) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        ValidateCiphertext(bytes1(uint8(MPC_TYPE.SUINT64_T)), ctUint64.unwrap(input.ciphertext), input.signature));
    }

    function onBoard(ctUint64 ct) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OnBoard(bytes1(uint8(MPC_TYPE.SUINT64_T)), ctUint64.unwrap(ct)));
    }

    function offBoard(gtUint64 pt) internal returns (ctUint64) {
        return ctUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoard(bytes1(uint8(MPC_TYPE.SUINT64_T)), gtUint64.unwrap(pt)));
    }

    function offBoardToUser(gtUint64 pt, address addr) internal returns (ctUint64) {
        return ctUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        OffBoardToUser(bytes1(uint8(MPC_TYPE.SUINT64_T)), gtUint64.unwrap(pt), abi.encodePacked(addr)));
    }

    function offBoardCombined(gtUint64 pt, address addr) internal returns (utUint64 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic64(uint64 pt) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        SetPublic(bytes1(uint8(MPC_TYPE.SUINT64_T)), uint256(pt)));
    }

    function rand64() internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).Rand(bytes1(uint8(MPC_TYPE.SUINT64_T))));
    }

    function randBoundedBits64(uint8 numBits) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).RandBoundedBits(bytes1(uint8(MPC_TYPE.SUINT64_T)), numBits));
    }

    function add(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function checkedAdd(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint64 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function sub(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function checkedSub(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint64 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function mul(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function checkedMul(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint64 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function div(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function gt(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function le(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function max(gtUint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function decrypt(gtUint64 ct) internal returns (uint64){
        return uint64(ExtendedOperations(address(MPC_PRECOMPILE)).
        Decrypt(bytes1(uint8(MPC_TYPE.SUINT64_T)), gtUint64.unwrap(ct)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint64 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint64.unwrap(b)));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }


    // =========== 128 bit operations ============

    function _splitUint128(uint128 number) private returns (uint64, uint64) {
        return (uint64(number >> 64), uint64(number));
    }

    function validateCiphertext(itUint128 memory input) internal returns (gtUint128 memory) {
        gtUint128 memory result;
        
        itUint64 memory highInput;
        highInput.ciphertext = input.ciphertext.high;
        highInput.signature = input.signature[0];
        
        itUint64 memory lowInput;
        lowInput.ciphertext = input.ciphertext.low;
        lowInput.signature = input.signature[1];
        
        result.high = validateCiphertext(highInput);
        result.low = validateCiphertext(lowInput);
        
        return result;
    }

    function onBoard(ctUint128 memory ct) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        result.high = onBoard(ct.high);
        result.low = onBoard(ct.low);

        return result;
    }

    function offBoard(gtUint128 memory pt) internal returns (ctUint128 memory) {
        ctUint128 memory result;

        result.high = offBoard(pt.high);
        result.low = offBoard(pt.low);

        return result;
    }

    function offBoardToUser(gtUint128 memory pt, address addr) internal returns (ctUint128 memory) {
        ctUint128 memory result;

        result.high = offBoardToUser(pt.high, addr);
        result.low = offBoardToUser(pt.low, addr);

        return result;
    }

    function offBoardCombined(gtUint128 memory pt, address addr) internal returns (utUint128 memory) {
        utUint128 memory result;

        result.ciphertext = offBoard(pt);
        result.userCiphertext = offBoardToUser(pt, addr);

        return result;
    }

    function setPublic128(uint128 pt) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        // Split the 128-bit value into high and low 64-bit parts
        uint64 low = uint64(pt);
        uint64 high = uint64(pt >> 64);
        
        result.high = setPublic64(high);
        result.low = setPublic64(low);
        
        return result;
    }

    function rand128() internal returns (gtUint128 memory) {
        gtUint128 memory result;

        result.high = rand64();
        result.low = rand64();

        return result;
    }

    function randBoundedBits128(uint8 numBits) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        uint8 numBits_ = numBits > 64 ? 64 : numBits;

        result.low = randBoundedBits64(numBits_);

        numBits_ = numBits > 64 ? numBits - 64 : 0;

        result.high = randBoundedBits64(numBits_);
        
        return result;
    }

    function add(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;
        
        // Add low parts
        result.low = add(a.low, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = add(a.high, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, add(result.high, uint64(1)));
        
        return result;
    }

    function checkedAdd(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;
        
        // Add low parts
        result.low = add(a.low, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = checkedAdd(a.high, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, checkedAdd(result.high, uint64(1)));
        
        return result;
    }

    function checkedAddWithOverflowBit(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool, gtUint128 memory) {
        gtBool bit = setPublic(false);
        gtUint128 memory result;
        
        // Add low parts
        result.low = add(a.low, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        (gtBool overflow, gtUint64 high) = checkedAddWithOverflowBit(a.high, b.high);
        (gtBool overflowWithCarry, gtUint64 highWithCarry) = checkedAddWithOverflowBit(high, uint64(1));

        // Handle carry if needed
        bit = mux(carry, overflow, or(overflow, overflowWithCarry));
        result.high = mux(carry, high, highWithCarry);
        
        return (bit, result);
    }

    function sub(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;
        
        // Subtract low parts
        result.low = sub(a.low, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = sub(a.high, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(borrow, result.high, sub(result.high, uint64(1)));
        
        return result;
    }

    function checkedSub(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;
        
        // Subtract low parts
        result.low = sub(a.low, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = checkedSub(a.high, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            checkedSub(
                mux(borrow, add(result.high, uint64(1)), result.high),
                uint64(1)
            )
        );
        
        return result;
    }

    function checkedSubWithOverflowBit(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool, gtUint128 memory) {
        gtBool bit = setPublic(false);
        gtUint128 memory result;
        
        // Subtract low parts
        result.low = sub(a.low, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, b.low);
        
        // Subtract high parts with borrow if needed
        (gtBool overflow, gtUint64 high) = checkedSubWithOverflowBit(a.high, b.high);
        (gtBool overflowWithCarry, gtUint64 highWithCarry) = checkedSubWithOverflowBit(high, uint64(1));

        // Handle borrow if needed
        bit = mux(borrow, overflow, or(overflow, overflowWithCarry));
        result.high = mux(borrow, high, highWithCarry);
        
        return (bit, result);
    }

    function _mul64(gtUint64 a, gtUint64 b) private returns (gtUint64, gtUint64) {
        uint64 MAX_UINT32 = uint64(type(uint32).max);

        gtUint64 pp0;
        gtUint64 pp1;
        gtUint64 pp2;
        gtUint64 pp3;

        {
            // Split the numbers into 32-bit parts
            gtUint64 aLow = and(a, MAX_UINT32);
            gtUint64 aHigh = shr(a, 32);
            gtUint64 bLow = and(b, MAX_UINT32);
            gtUint64 bHigh = shr(b, 32);

            // Compute partial products
            pp0 = mul(aLow, bLow);
            pp1 = mul(aLow, bHigh);
            pp2 = mul(aHigh, bLow);
            pp3 = mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint64 mid = add(
            add(
                shr(pp0, 32),
                and(pp1, MAX_UINT32)
            ),
            and(pp2, MAX_UINT32)
        );
        gtUint64 carry = shr(mid, 32);

        gtUint64 high = add(
            add(pp3, shr(pp1, 32)),
            add(shr(pp2, 32), carry)
        );
        gtUint64 low = or(
            and(pp0, MAX_UINT32),
            shl(and(mid, MAX_UINT32), 32)
        );

        return (high, low);
    }

    function mul(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(a.low, b.low);
        (, gtUint64 pp1) = _mul64(a.high, b.low);
        (, gtUint64 pp2) = _mul64(a.low, b.high);

        // Compute the high and low parts
        result.high = add(
            add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function checkedMul(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(a.low, b.low);
        (gtUint64 pp2, gtUint64 pp1) = _mul64(a.high, b.low);
        (gtUint64 pp4, gtUint64 pp3) = _mul64(a.low, b.high);
        (gtUint64 pp6, gtUint64 pp5) = _mul64(a.high, b.high);

        // Compute the high and low parts
        result.high = checkedAdd(
            checkedAdd(pp0, pp1),
            pp3
        );
        result.low = low;

        // Check for overflow
        checkedSub(
            uint64(0),
            add(
                add(pp2, pp4),
                add(pp5, pp6)
            )
        );
        
        return result;
    }

    function checkedMulWithOverflowBit(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool, gtUint128 memory) {
        gtUint128 memory result;

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(a.low, b.low);
        (gtUint64 pp2, gtUint64 pp1) = _mul64(a.high, b.low);
        (gtUint64 pp4, gtUint64 pp3) = _mul64(a.low, b.high);
        (gtUint64 pp6, gtUint64 pp5) = _mul64(a.high, b.high);

        // Compute the high and low parts
        gtBool overflow1;

        (gtBool overflow0, gtUint64 high) = checkedAddWithOverflowBit(pp0, pp1);
        (overflow1, result.high) = checkedAddWithOverflowBit(high, pp3);

        result.low = low;

        // Check for overflow
        gtBool bit = or(
            or(overflow0, overflow1),
            gt(
                add(
                    add(pp2, pp4),
                    add(pp5, pp6)
                ),
                uint64(0)
            )
        );
        
        return (bit, result);
    }

    function and(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        result.low = and(a.low, b.low);
        result.high = and(a.high, b.high);
        
        return result;
    }

    function or(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        result.low = or(a.low, b.low);
        result.high = or(a.high, b.high);
        
        return result;
    }

    function xor(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        result.low = xor(a.low, b.low);
        result.high = xor(a.high, b.high);
        
        return result;
    }

    function eq(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool) {
        return and(eq(a.low, b.low), eq(a.high, b.high));
    }

    function ne(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool) {
        return or(ne(a.low, b.low), ne(a.high, b.high));
    }

    function ge(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, gt(a.high, b.high), ge(a.low, b.low));
    }

    function gt(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, gt(a.high, b.high), gt(a.low, b.low));
    }

    function le(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, lt(a.high, b.high), le(a.low, b.low));
    }

    function lt(gtUint128 memory a, gtUint128 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, lt(a.high, b.high), lt(a.low, b.low));
    }

    function min(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool aHighLessThan = lt(a.high, b.high);
        gtBool aLowLessThan = lt(a.low, b.low);

        return mux(
            highEqual,
            mux(aHighLessThan, b, a),
            mux(aLowLessThan, b, a)
        );
    }

    function max(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool aHighGreaterThan = gt(a.high, b.high);
        gtBool aLowGreaterThan = gt(a.low, b.low);

        return mux(
            highEqual,
            mux(aHighGreaterThan, b, a),
            mux(aLowGreaterThan, b, a)
        );
    }

    function decrypt(gtUint128 memory ct) internal returns (uint128) {
        uint64 highPart = decrypt(ct.high);
        uint64 lowPart = decrypt(ct.low);
        
        // Combine high and low parts
        return uint128(highPart) << 64 | uint128(lowPart);
    }

    function mux(gtBool bit, gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        result.low = mux(bit, a.low, b.low);
        result.high = mux(bit, a.high, b.high);
        
        return result;
    }

    function transfer(gtUint128 memory a, gtUint128 memory b, gtUint128 memory amount) internal returns (gtUint128 memory, gtUint128 memory, gtBool) {
        gtBool success = MpcCore.ge(a, amount);

        gtUint128 memory a_ = MpcCore.mux(success, a, MpcCore.sub(a, amount));
        gtUint128 memory b_ = MpcCore.mux(success, b, MpcCore.add(b, amount));
        
        return (a_, b_, success);
    }

    function transferWithAllowance(gtUint128 memory a, gtUint128 memory b, gtUint128 memory amount, gtUint128 memory allowance) internal returns (gtUint128 memory, gtUint128 memory, gtBool, gtUint128 memory) {
        gtBool success = MpcCore.and(MpcCore.ge(a, amount), MpcCore.le(amount, allowance));

        gtUint128 memory a_ = MpcCore.mux(success, a, MpcCore.sub(a, amount));
        gtUint128 memory b_ = MpcCore.mux(success, b, MpcCore.add(b, amount));
        gtUint128 memory allowance_ = MpcCore.mux(success, allowance, MpcCore.sub(allowance, amount));
        
        return (a_, b_, success, allowance_);
    }

    // =========== 256 bit operations ============

    function _splitUint256(uint256 number) private returns (uint128, uint128) {
        return (uint128(number >> 128), uint128(number));
    }

    function validateCiphertext(itUint256 memory input) internal returns (gtUint256 memory) {
        gtUint256 memory result;
        
        itUint128 memory highInput;
        highInput.ciphertext = input.ciphertext.high;
        highInput.signature = input.signature[0];
        
        itUint128 memory lowInput;
        lowInput.ciphertext = input.ciphertext.low;
        lowInput.signature = input.signature[1];
        
        result.high = validateCiphertext(highInput);
        result.low = validateCiphertext(lowInput);
        
        return result;
    }

    function onBoard(ctUint256 memory ct) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        result.high = onBoard(ct.high);
        result.low = onBoard(ct.low);

        return result;
    }

    function offBoard(gtUint256 memory pt) internal returns (ctUint256 memory) {
        ctUint256 memory result;

        result.high = offBoard(pt.high);
        result.low = offBoard(pt.low);

        return result;
    }

    function offBoardToUser(gtUint256 memory pt, address addr) internal returns (ctUint256 memory) {
        ctUint256 memory result;

        result.high = offBoardToUser(pt.high, addr);
        result.low = offBoardToUser(pt.low, addr);

        return result;
    }

    function offBoardCombined(gtUint256 memory pt, address addr) internal returns (utUint256 memory) {
        utUint256 memory result;

        result.ciphertext = offBoard(pt);
        result.userCiphertext = offBoardToUser(pt, addr);

        return result;
    }

    function setPublic256(uint256 pt) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        // Split the 256-bit value into high and low 128-bit parts
        uint128 low = uint128(pt);
        uint128 high = uint128(pt >> 128);
        
        result.high = setPublic128(high);
        result.low = setPublic128(low);
        
        return result;
    }

    function rand256() internal returns (gtUint256 memory) {
        gtUint256 memory result;

        result.high = rand128();
        result.low = rand128();

        return result;
    }

    function randBoundedBits256(uint8 numBits) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        uint8 numBits_ = numBits > 128 ? 128 : numBits;

        result.low = randBoundedBits128(numBits_);

        numBits_ = numBits > 128 ? numBits - 128 : 0;

        result.high = randBoundedBits128(numBits_);
        
        return result;
    }

    function add(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;
        
        // Add low parts
        result.low = add(a.low, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = add(a.high, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, add(result.high, uint128(1)));
        
        return result;
    }

    function checkedAdd(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;
        
        // Add low parts
        result.low = add(a.low, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = checkedAdd(a.high, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, checkedAdd(result.high, uint128(1)));
        
        return result;
    }

    function checkedAddWithOverflowBit(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool, gtUint256 memory) {
        gtBool bit = setPublic(false);
        gtUint256 memory result;
        
        // Add low parts
        result.low = add(a.low, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        (gtBool overflow, gtUint128 memory high) = checkedAddWithOverflowBit(a.high, b.high);
        (gtBool overflowWithCarry, gtUint128 memory highWithCarry) = checkedAddWithOverflowBit(high, uint128(1));

        // Handle carry if needed
        bit = mux(carry, overflow, or(overflow, overflowWithCarry));
        result.high = mux(carry, high, highWithCarry);
        
        return (bit, result);
    }

    function sub(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;
        
        // Subtract low parts
        result.low = sub(a.low, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = sub(a.high, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(borrow, result.high, sub(result.high, uint128(1)));
        
        return result;
    }

    function checkedSub(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;
        
        // Subtract low parts
        result.low = sub(a.low, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = checkedSub(a.high, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            checkedSub(
                mux(borrow, add(result.high, uint128(1)), result.high),
                uint128(1)
            )
        );
        
        return result;
    }

    function checkedSubWithOverflowBit(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool, gtUint256 memory) {
        gtBool bit = setPublic(false);
        gtUint256 memory result;
        
        // Subtract low parts
        result.low = sub(a.low, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, b.low);
        
        // Subtract high parts with borrow if needed
        (gtBool overflow, gtUint128 memory high) = checkedSubWithOverflowBit(a.high, b.high);
        (gtBool overflowWithCarry, gtUint128 memory highWithCarry) = checkedSubWithOverflowBit(high, uint128(1));

        // Handle borrow if needed
        bit = mux(borrow, overflow, or(overflow, overflowWithCarry));
        result.high = mux(borrow, high, highWithCarry);
        
        return (bit, result);
    }

    function _mul128(gtUint128 memory a, gtUint128 memory b) private returns (gtUint128 memory, gtUint128 memory) {
        uint128 MAX_UINT64 = uint128(type(uint64).max);

        gtUint128 memory pp0;
        gtUint128 memory pp1;
        gtUint128 memory pp2;
        gtUint128 memory pp3;

        {
            // Split the numbers into 32-bit parts
            gtUint128 memory aLow = and(a, MAX_UINT64);
            gtUint128 memory aHigh = shr(a, 64);
            gtUint128 memory bLow = and(b, MAX_UINT64);
            gtUint128 memory bHigh = shr(b, 64);

            // Compute partial products
            pp0 = mul(aLow, bLow);
            pp1 = mul(aLow, bHigh);
            pp2 = mul(aHigh, bLow);
            pp3 = mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint128 memory mid = add(
            add(
                shr(pp0, 64),
                and(pp1, MAX_UINT64)
            ),
            and(pp2, MAX_UINT64)
        );
        gtUint128 memory carry = shr(mid, 64);

        gtUint128 memory high = add(
            add(pp3, shr(pp1, 64)),
            add(shr(pp2, 64), carry)
        );
        gtUint128 memory low = or(
            and(pp0, MAX_UINT64),
            shl(and(mid, MAX_UINT64), 64)
        );

        return (high, low);
    }

    function mul(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(a.low, b.low);
        (, gtUint128 memory pp1) = _mul128(a.high, b.low);
        (, gtUint128 memory pp2) = _mul128(a.low, b.high);

        // Compute the high and low parts
        result.high = add(
            add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function checkedMul(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(a.low, b.low);
        (gtUint128 memory pp2, gtUint128 memory pp1) = _mul128(a.high, b.low);
        (gtUint128 memory pp4, gtUint128 memory pp3) = _mul128(a.low, b.high);
        (gtUint128 memory pp6, gtUint128 memory pp5) = _mul128(a.high, b.high);

        // Compute the high and low parts
        result.high = checkedAdd(
            checkedAdd(pp0, pp1),
            pp3
        );
        result.low = low;

        // Check for overflow
        checkedSub(
            uint128(0),
            add(
                add(pp2, pp4),
                add(pp5, pp6)
            )
        );
        
        return result;
    }

    function checkedMulWithOverflowBit(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool, gtUint256 memory) {
        gtUint256 memory result;

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(a.low, b.low);
        (gtUint128 memory pp2, gtUint128 memory pp1) = _mul128(a.high, b.low);
        (gtUint128 memory pp4, gtUint128 memory pp3) = _mul128(a.low, b.high);
        (gtUint128 memory pp6, gtUint128 memory pp5) = _mul128(a.high, b.high);

        // Compute the high and low parts
        gtBool overflow1;

        (gtBool overflow0, gtUint128 memory high) = checkedAddWithOverflowBit(pp0, pp1);
        (overflow1, result.high) = checkedAddWithOverflowBit(high, pp3);

        result.low = low;

        // Check for overflow
        gtBool bit = or(
            or(overflow0, overflow1),
            gt(
                add(
                    add(pp2, pp4),
                    add(pp5, pp6)
                ),
                uint128(0)
            )
        );
        
        return (bit, result);
    }

    function and(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        result.low = and(a.low, b.low);
        result.high = and(a.high, b.high);
        
        return result;
    }

    function or(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        result.low = or(a.low, b.low);
        result.high = or(a.high, b.high);
        
        return result;
    }

    function xor(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        result.low = xor(a.low, b.low);
        result.high = xor(a.high, b.high);
        
        return result;
    }

    function eq(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool) {
        return and(eq(a.low, b.low), eq(a.high, b.high));
    }

    function ne(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool) {
        return or(ne(a.low, b.low), ne(a.high, b.high));
    }

    function ge(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, gt(a.high, b.high), ge(a.low, b.low));
    }

    function gt(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, gt(a.high, b.high), gt(a.low, b.low));
    }

    function le(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, lt(a.high, b.high), le(a.low, b.low));
    }

    function lt(gtUint256 memory a, gtUint256 memory b) internal returns (gtBool) {
        gtBool highEqual = eq(a.high, b.high);

        return mux(highEqual, lt(a.high, b.high), lt(a.low, b.low));
    }

    function min(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool aHighLessThan = lt(a.high, b.high);
        gtBool aLowLessThan = lt(a.low, b.low);

        return mux(
            highEqual,
            mux(aHighLessThan, b, a),
            mux(aLowLessThan, b, a)
        );
    }

    function max(gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtBool highEqual = eq(a.high, b.high);
        gtBool aHighGreaterThan = gt(a.high, b.high);
        gtBool aLowGreaterThan = gt(a.low, b.low);

        return mux(
            highEqual,
            mux(aHighGreaterThan, b, a),
            mux(aLowGreaterThan, b, a)
        );
    }

    function decrypt(gtUint256 memory ct) internal returns (uint256) {
        uint128 highPart = decrypt(ct.high);
        uint128 lowPart = decrypt(ct.low);
        
        // Combine high and low parts
        return uint256(highPart) << 128 | uint256(lowPart);
    }

    function mux(gtBool bit, gtUint256 memory a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        result.low = mux(bit, a.low, b.low);
        result.high = mux(bit, a.high, b.high);
        
        return result;
    }

    function transfer(gtUint256 memory a, gtUint256 memory b, gtUint256 memory amount) internal returns (gtUint256 memory, gtUint256 memory, gtBool) {
        gtBool success = MpcCore.ge(a, amount);

        gtUint256 memory a_ = MpcCore.mux(success, a, MpcCore.sub(a, amount));
        gtUint256 memory b_ = MpcCore.mux(success, b, MpcCore.add(b, amount));
        
        return (a_, b_, success);
    }

    function transferWithAllowance(gtUint256 memory a, gtUint256 memory b, gtUint256 memory amount, gtUint256 memory allowance) internal returns (gtUint256 memory, gtUint256 memory, gtBool, gtUint256 memory) {
        gtBool success = MpcCore.and(MpcCore.ge(a, amount), MpcCore.le(amount, allowance));

        gtUint256 memory a_ = MpcCore.mux(success, a, MpcCore.sub(a, amount));
        gtUint256 memory b_ = MpcCore.mux(success, b, MpcCore.add(b, amount));
        gtUint256 memory allowance_ = MpcCore.mux(success, allowance, MpcCore.sub(allowance, amount));
        
        return (a_, b_, success, allowance_);
    }

    // =========== String operations ============

    function validateCiphertext(itString memory input) internal returns (gtString memory) {
        uint256 len_ = input.signature.length;

        require(input.ciphertext.value.length == len_, "MPC_CORE: INVALID_INPUT_TEXT");

        gtString memory gt_ = gtString(new gtUint64[](len_));

        itUint64 memory it_;

        for (uint256 i = 0; i < len_; ++i) {
            it_.ciphertext = input.ciphertext.value[i];
            it_.signature = input.signature[i];

            gt_.value[i] = validateCiphertext(it_);
        }

        return gt_;
    }

    function onBoard(ctString memory ct) internal returns (gtString memory) {
        uint256 len_ = ct.value.length;

        gtString memory gt_ = gtString(new gtUint64[](len_));

        for (uint256 i = 0; i < len_; ++i) {
            gt_.value[i] = onBoard(ct.value[i]);
        }

        return gt_;
    }

    function offBoard(gtString memory pt) internal returns (ctString memory) {
        uint256 len_ = pt.value.length;

        ctString memory ct_ = ctString(new ctUint64[](len_));

        for (uint256 i = 0; i < len_; ++i) {
            ct_.value[i] = offBoard(pt.value[i]);
        }

        return ct_;
    }

    function offBoardToUser(gtString memory pt, address addr) internal returns (ctString memory) {
        uint256 len_ = pt.value.length;

        ctString memory ct_ = ctString(new ctUint64[](len_));

        for (uint256 i = 0; i < len_; ++i) {
            ct_.value[i] = offBoardToUser(pt.value[i], addr);
        }

        return ct_;
    }

    function offBoardCombined(gtString memory pt, address addr) internal returns (utString memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublicString(string memory pt) internal returns (gtString memory) {
        bytes memory strBytes_ = bytes(pt);
        uint256 len_ = strBytes_.length;
        uint256 count_ = (len_ + 7) / 8; // Number of bytes8 elements needed

        gtString memory result_ = gtString(new gtUint64[](count_));

        bytes8 cell_;

        for (uint256 i = 0; i < count_ * 8; ++i) {
            if (i % 8 == 0) {
                cell_ = bytes8(0);
            } else {
                cell_ <<= 8;
            }

            if (i < len_) {
                cell_ |= bytes8(strBytes_[i]) >> 56;
            }

            if (i % 8 == 7) {
                result_.value[i / 8] = setPublic64(uint64(cell_));
            }
        }

        return result_;
    }

    function decrypt(gtString memory ct) internal returns (string memory){
        uint256 len_ = ct.value.length;
        bytes memory result_ = new bytes(len_ * 8);

        bytes8 temp_;

        uint256 resultIndex;
        
        for (uint256 i = 0; i < len_; ++i) {
            temp_ = bytes8(decrypt(ct.value[i]));

            assembly {
                // Copy the bytes directly into the result array using assembly.
                mstore(add(result_, add(0x20, resultIndex)), temp_)
            }

            resultIndex += 8;
        }

        return string(result_);
    }

    function eq(gtString memory a, gtString memory b) internal returns (gtBool) {
        uint256 len = a.value.length;

        // note that we are not leaking information since the array length is visible to all
        if (len != b.value.length) return setPublic(false);

        gtBool result_ = eq(a.value[0], b.value[0]);

        for (uint256 i = 1; i < len; ++i) {
            result_ = and(result_, eq(a.value[i], b.value[i]));
        }

        return result_;
    }

    function ne(gtString memory a, gtString memory b) internal returns (gtBool) {
        uint256 len = a.value.length;

        // note that we are not leaking information since the array length is visible to all
        if (len != b.value.length) return setPublic(true);

        gtBool result_ = ne(a.value[0], b.value[0]);

        for (uint256 i = 1; i < len; ++i) {
            result_ = or(result_, ne(a.value[i], b.value[i]));
        }

        return result_;
    }


    // =========== Operations with LHS_PUBLIC parameter ===========
    // =========== 8 bit operations ==============

    function add(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function checkedAdd(uint8 a, gtUint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedAddWithOverflowBit(uint8 a, gtUint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function sub(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function checkedSub(uint8 a, gtUint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedSubWithOverflowBit(uint8 a, gtUint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function mul(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function checkedMul(uint8 a, gtUint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedMulWithOverflowBit(uint8 a, gtUint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function div(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function rem(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function and(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function or(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function xor(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function eq(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function ne(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function ge(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function gt(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function le(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function lt(uint8 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function min(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function max(uint8 a, gtUint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), uint256(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, uint8 a, gtUint8 b) internal returns (gtUint8){
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtBool.unwrap(bit), uint256(a), gtUint8.unwrap(b)));
    }


    // =========== 16 bit operations ==============

    function add(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function checkedAdd(uint16 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedAddWithOverflowBit(uint16 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function sub(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function checkedSub(uint16 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedSubWithOverflowBit(uint16 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function mul(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function checkedMul(uint16 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedMulWithOverflowBit(uint16 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function div(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function rem(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function and(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function or(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function xor(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function eq(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function ne(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function ge(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function gt(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function le(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function lt(uint16 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function min(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function max(uint16 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), uint256(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, uint16 a, gtUint16 b) internal returns (gtUint16){
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtBool.unwrap(bit), uint256(a), gtUint16.unwrap(b)));
    }


    // =========== 32 bit operations ==============

    function add(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function checkedAdd(uint32 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(uint32 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function sub(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function checkedSub(uint32 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(uint32 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function mul(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function checkedMul(uint32 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(uint32 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function div(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function rem(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function and(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function or(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function xor(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function eq(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function ne(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function ge(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function gt(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function le(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function lt(uint32 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function min(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function max(uint32 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), uint256(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, uint32 a, gtUint32 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtBool.unwrap(bit), uint256(a), gtUint32.unwrap(b)));
    }


    // =========== 64 bit operations ==============

    function add(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function checkedAdd(uint64 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(uint64 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function sub(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function checkedSub(uint64 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(uint64 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function mul(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function checkedMul(uint64 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(uint64 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function div(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function rem(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function and(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function or(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function xor(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function eq(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function ne(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function ge(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function gt(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function le(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function lt(uint64 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function min(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function max(uint64 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), uint256(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, uint64 a, gtUint64 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtBool.unwrap(bit), uint256(a), gtUint64.unwrap(b)));
    }


    // =========== 128 bit operations ===========

    function add(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);
        
        // Add low parts
        result.low = add(aLow, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, aLow);
        
        // Add high parts with carry if needed
        result.high = add(aHigh, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, add(result.high, uint64(1)));
        
        return result;
    }

    function checkedAdd(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);
        
        // Add low parts
        result.low = add(aLow, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, aLow);
        
        // Add high parts with carry if needed
        result.high = checkedAdd(aHigh, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, checkedAdd(result.high, uint64(1)));
        
        return result;
    }

    function checkedAddWithOverflowBit(uint128 a, gtUint128 memory b) internal returns (gtBool, gtUint128 memory) {
        gtBool bit = setPublic(false);
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);
        
        // Add low parts
        result.low = add(aLow, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, aLow);
        
        // Add high parts with carry if needed
        (gtBool overflow, gtUint64 high) = checkedAddWithOverflowBit(aHigh, b.high);
        (gtBool overflowWithCarry, gtUint64 highWithCarry) = checkedAddWithOverflowBit(high, uint64(1));

        // Handle carry if needed
        bit = mux(carry, overflow, or(overflow, overflowWithCarry));
        result.high = mux(carry, high, highWithCarry);
        
        return (bit, result);
    }

    function sub(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);
        
        // Subtract low parts
        result.low = sub(aLow, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(aLow, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = sub(aHigh, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(borrow, result.high, sub(result.high, uint64(1)));
        
        return result;
    }

    function checkedSub(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);
        
        // Subtract low parts
        result.low = sub(aLow, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(aLow, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = checkedSub(aHigh, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            checkedSub(
                mux(borrow, add(result.high, uint64(1)), result.high),
                uint64(1)
            )
        );
        
        return result;
    }

    function checkedSubWithOverflowBit(uint128 a, gtUint128 memory b) internal returns (gtBool, gtUint128 memory) {
        gtBool bit = setPublic(false);
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);
        
        // Subtract low parts
        result.low = sub(aLow, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(aLow, b.low);
        
        // Subtract high parts with borrow if needed
        (gtBool overflow, gtUint64 high) = checkedSubWithOverflowBit(aHigh, b.high);
        (gtBool overflowWithCarry, gtUint64 highWithCarry) = checkedSubWithOverflowBit(high, uint64(1));

        // Handle borrow if needed
        bit = mux(borrow, overflow, or(overflow, overflowWithCarry));
        result.high = mux(borrow, high, highWithCarry);
        
        return (bit, result);
    }

    function _mul64(uint64 a, gtUint64 b) private returns (gtUint64, gtUint64) {
        uint64 MAX_UINT32 = uint64(type(uint32).max);

        gtUint64 pp0;
        gtUint64 pp1;
        gtUint64 pp2;
        gtUint64 pp3;

        {
            // Split the numbers into 32-bit parts
            uint64 aLow = a & type(uint32).max;
            uint64 aHigh = a >> 32;
            gtUint64 bLow = and(b, MAX_UINT32);
            gtUint64 bHigh = shr(b, 32);

            // Compute partial products
            pp0 = mul(aLow, bLow);
            pp1 = mul(aLow, bHigh);
            pp2 = mul(aHigh, bLow);
            pp3 = mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint64 mid = add(
            add(
                shr(pp0, 32),
                and(pp1, MAX_UINT32)
            ),
            and(pp2, MAX_UINT32)
        );
        gtUint64 carry = shr(mid, 32);

        gtUint64 high = add(
            add(pp3, shr(pp1, 32)),
            add(shr(pp2, 32), carry)
        );
        gtUint64 low = or(
            and(pp0, MAX_UINT32),
            shl(and(mid, MAX_UINT32), 32)
        );

        return (high, low);
    }

    function mul(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        uint64 aLow = uint64(a & type(uint64).max);
        uint64 aHigh = uint64(a >> 64);

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(aLow, b.low);
        (, gtUint64 pp1) = _mul64(aHigh, b.low);
        (, gtUint64 pp2) = _mul64(aLow, b.high);

        // Compute the high and low parts
        result.high = add(
            add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function checkedMul(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        uint64 aLow = uint64(a & type(uint64).max);
        uint64 aHigh = uint64(a >> 64);

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(aLow, b.low);
        (gtUint64 pp2, gtUint64 pp1) = _mul64(aHigh, b.low);
        (gtUint64 pp4, gtUint64 pp3) = _mul64(aLow, b.high);
        (gtUint64 pp6, gtUint64 pp5) = _mul64(aHigh, b.high);

        // Compute the high and low parts
        result.high = checkedAdd(
            checkedAdd(pp0, pp1),
            pp3
        );
        result.low = low;

        // Check for overflow
        checkedSub(
            uint64(0),
            add(
                add(pp2, pp4),
                add(pp5, pp6)
            )
        );
        
        return result;
    }

    function checkedMulWithOverflowBit(uint128 a, gtUint128 memory b) internal returns (gtBool, gtUint128 memory) {
        gtUint128 memory result;

        gtUint64 low;
        gtUint64 pp0;
        gtUint64 pp1;
        gtUint64 pp2;
        gtUint64 pp3;
        gtUint64 pp4;
        gtUint64 pp5;
        gtUint64 pp6;

        {
            uint64 aLow = uint64(a & type(uint64).max);
            uint64 aHigh = uint64(a >> 64);

            // Compute partial products
            (pp0, low) = _mul64(aLow, b.low);
            (pp2, pp1) = _mul64(aHigh, b.low);
            (pp4, pp3) = _mul64(aLow, b.high);
            (pp6, pp5) = _mul64(aHigh, b.high);
        }

        // Compute the high and low parts
        gtBool overflow1;

        (gtBool overflow0, gtUint64 high) = checkedAddWithOverflowBit(pp0, pp1);
        (overflow1, result.high) = checkedAddWithOverflowBit(high, pp3);

        result.low = low;

        // Check for overflow
        gtBool bit = or(
            or(overflow0, overflow1),
            gt(
                add(
                    add(pp2, pp4),
                    add(pp5, pp6)
                ),
                uint64(0)
            )
        );
        
        return (bit, result);
    }

    function and(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        result.low = and(aLow, b.low);
        result.high = and(aHigh, b.high);
        
        return result;
    }

    function or(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        result.low = or(aLow, b.low);
        result.high = or(aHigh, b.high);
        
        return result;
    }

    function xor(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        result.low = xor(aLow, b.low);
        result.high = xor(aHigh, b.high);
        
        return result;
    }

    function eq(uint128 a, gtUint128 memory b) internal returns (gtBool) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        return and(eq(aLow, b.low), eq(aHigh, b.high));
    }

    function ne(uint128 a, gtUint128 memory b) internal returns (gtBool) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        return or(ne(aLow, b.low), ne(aHigh, b.high));
    }

    function ge(uint128 a, gtUint128 memory b) internal returns (gtBool) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, gt(aHigh, b.high), ge(aLow, b.low));
    }

    function gt(uint128 a, gtUint128 memory b) internal returns (gtBool) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, gt(aHigh, b.high), gt(aLow, b.low));
    }

    function le(uint128 a, gtUint128 memory b) internal returns (gtBool) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, lt(aHigh, b.high), le(aLow, b.low));
    }

    function lt(uint128 a, gtUint128 memory b) internal returns (gtBool) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, lt(aHigh, b.high), lt(aLow, b.low));
    }

    function min(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        gtBool highEqual = eq(aHigh, b.high);
        gtBool aHighLessThan = lt(aHigh, b.high);
        gtBool aLowLessThan = lt(aLow, b.low);

        return mux(
            highEqual,
            mux(aHighLessThan, b, a),
            mux(aLowLessThan, b, a)
        );
    }

    function max(uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        gtBool highEqual = eq(aHigh, b.high);
        gtBool aHighGreaterThan = gt(aHigh, b.high);
        gtBool aLowGreaterThan = gt(aLow, b.low);

        return mux(
            highEqual,
            mux(aHighGreaterThan, b, a),
            mux(aLowGreaterThan, b, a)
        );
    }

    function mux(gtBool bit, uint128 a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 aHigh, uint64 aLow) = _splitUint128(a);

        result.low = mux(bit, aLow, b.low);
        result.high = mux(bit, aHigh, b.high);
        
        return result;
    }


    // =========== 256 bit operations ===========

    function add(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);
        
        // Add low parts
        result.low = add(aLow, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, aLow);
        
        // Add high parts with carry if needed
        result.high = add(aHigh, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, add(result.high, uint128(1)));
        
        return result;
    }

    function checkedAdd(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);
        
        // Add low parts
        result.low = add(aLow, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, aLow);
        
        // Add high parts with carry if needed
        result.high = checkedAdd(aHigh, b.high);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, checkedAdd(result.high, uint128(1)));
        
        return result;
    }

    function checkedAddWithOverflowBit(uint256 a, gtUint256 memory b) internal returns (gtBool, gtUint256 memory) {
        gtBool bit = setPublic(false);
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);
        
        // Add low parts
        result.low = add(aLow, b.low);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, aLow);
        
        // Add high parts with carry if needed
        (gtBool overflow, gtUint128 memory high) = checkedAddWithOverflowBit(aHigh, b.high);
        (gtBool overflowWithCarry, gtUint128 memory highWithCarry) = checkedAddWithOverflowBit(high, uint128(1));

        // Handle carry if needed
        bit = mux(carry, overflow, or(overflow, overflowWithCarry));
        result.high = mux(carry, high, highWithCarry);
        
        return (bit, result);
    }

    function sub(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);
        
        // Subtract low parts
        result.low = sub(aLow, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(aLow, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = sub(aHigh, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(borrow, result.high, sub(result.high, uint128(1)));
        
        return result;
    }

    function checkedSub(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);
        
        // Subtract low parts
        result.low = sub(aLow, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(aLow, b.low);
        
        // Subtract high parts with borrow if needed
        result.high = checkedSub(aHigh, b.high);
        
        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            checkedSub(
                mux(borrow, add(result.high, uint128(1)), result.high),
                uint128(1)
            )
        );
        
        return result;
    }

    function checkedSubWithOverflowBit(uint256 a, gtUint256 memory b) internal returns (gtBool, gtUint256 memory) {
        gtBool bit = setPublic(false);
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);
        
        // Subtract low parts
        result.low = sub(aLow, b.low);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(aLow, b.low);
        
        // Subtract high parts with borrow if needed
        (gtBool overflow, gtUint128 memory high) = checkedSubWithOverflowBit(aHigh, b.high);
        (gtBool overflowWithCarry, gtUint128 memory highWithCarry) = checkedSubWithOverflowBit(high, uint128(1));

        // Handle borrow if needed
        bit = mux(borrow, overflow, or(overflow, overflowWithCarry));
        result.high = mux(borrow, high, highWithCarry);
        
        return (bit, result);
    }

    function _mul128(uint128 a, gtUint128 memory b) private returns (gtUint128 memory, gtUint128 memory) {
        uint128 MAX_UINT64 = uint128(type(uint64).max);

        gtUint128 memory pp0;
        gtUint128 memory pp1;
        gtUint128 memory pp2;
        gtUint128 memory pp3;

        {
            // Split the numbers into 64-bit parts
            uint128 aLow = a & type(uint64).max;
            uint128 aHigh = a >> 64;
            gtUint128 memory bLow = and(b, MAX_UINT64);
            gtUint128 memory bHigh = shr(b, 64);

            // Compute partial products
            pp0 = mul(aLow, bLow);
            pp1 = mul(aLow, bHigh);
            pp2 = mul(aHigh, bLow);
            pp3 = mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint128 memory mid = add(
            add(
                shr(pp0, 64),
                and(pp1, MAX_UINT64)
            ),
            and(pp2, MAX_UINT64)
        );
        gtUint128 memory carry = shr(mid, 64);

        gtUint128 memory high = add(
            add(pp3, shr(pp1, 64)),
            add(shr(pp2, 64), carry)
        );
        gtUint128 memory low = or(
            and(pp0, MAX_UINT64),
            shl(and(mid, MAX_UINT64), 64)
        );

        return (high, low);
    }

    function mul(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(aLow, b.low);
        (, gtUint128 memory pp1) = _mul128(aHigh, b.low);
        (, gtUint128 memory pp2) = _mul128(aLow, b.high);

        // Compute the high and low parts
        result.high = add(
            add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function checkedMul(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(aLow, b.low);
        (gtUint128 memory pp2, gtUint128 memory pp1) = _mul128(aHigh, b.low);
        (gtUint128 memory pp4, gtUint128 memory pp3) = _mul128(aLow, b.high);
        (gtUint128 memory pp6, gtUint128 memory pp5) = _mul128(aHigh, b.high);

        // Compute the high and low parts
        result.high = checkedAdd(
            checkedAdd(pp0, pp1),
            pp3
        );
        result.low = low;

        // Check for overflow
        checkedSub(
            uint128(0),
            add(
                add(pp2, pp4),
                add(pp5, pp6)
            )
        );
        
        return result;
    }

    function checkedMulWithOverflowBit(uint256 a, gtUint256 memory b) internal returns (gtBool, gtUint256 memory) {
        gtUint256 memory result;

        gtUint128 memory low;
        gtUint128 memory pp0;
        gtUint128 memory pp1;
        gtUint128 memory pp2;
        gtUint128 memory pp3;
        gtUint128 memory pp4;
        gtUint128 memory pp5;
        gtUint128 memory pp6;

        {
            (uint128 aHigh, uint128 aLow) = _splitUint256(a);

            // Compute partial products
            (pp0, low) = _mul128(aLow, b.low);
            (pp2, pp1) = _mul128(aHigh, b.low);
            (pp4, pp3) = _mul128(aLow, b.high);
            (pp6, pp5) = _mul128(aHigh, b.high);
        }

        // Compute the high and low parts
        gtBool overflow1;

        (gtBool overflow0, gtUint128 memory high) = checkedAddWithOverflowBit(pp0, pp1);
        (overflow1, result.high) = checkedAddWithOverflowBit(high, pp3);

        result.low = low;

        // Check for overflow
        gtBool bit = or(
            or(overflow0, overflow1),
            gt(
                add(
                    add(pp2, pp4),
                    add(pp5, pp6)
                ),
                uint128(0)
            )
        );
        
        return (bit, result);
    }

    function and(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        result.low = and(aLow, b.low);
        result.high = and(aHigh, b.high);
        
        return result;
    }

    function or(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        result.low = or(aLow, b.low);
        result.high = or(aHigh, b.high);
        
        return result;
    }

    function xor(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        result.low = xor(aLow, b.low);
        result.high = xor(aHigh, b.high);
        
        return result;
    }

    function eq(uint256 a, gtUint256 memory b) internal returns (gtBool) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        return and(eq(aLow, b.low), eq(aHigh, b.high));
    }

    function ne(uint256 a, gtUint256 memory b) internal returns (gtBool) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        return or(ne(aLow, b.low), ne(aHigh, b.high));
    }

    function ge(uint256 a, gtUint256 memory b) internal returns (gtBool) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, gt(aHigh, b.high), ge(aLow, b.low));
    }

    function gt(uint256 a, gtUint256 memory b) internal returns (gtBool) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, gt(aHigh, b.high), gt(aLow, b.low));
    }

    function le(uint256 a, gtUint256 memory b) internal returns (gtBool) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, lt(aHigh, b.high), le(aLow, b.low));
    }

    function lt(uint256 a, gtUint256 memory b) internal returns (gtBool) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        gtBool highEqual = eq(aHigh, b.high);

        return mux(highEqual, lt(aHigh, b.high), lt(aLow, b.low));
    }

    function min(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        gtBool highEqual = eq(aHigh, b.high);
        gtBool aHighLessThan = lt(aHigh, b.high);
        gtBool aLowLessThan = lt(aLow, b.low);

        return mux(
            highEqual,
            mux(aHighLessThan, b, a),
            mux(aLowLessThan, b, a)
        );
    }

    function max(uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        gtBool highEqual = eq(aHigh, b.high);
        gtBool aHighGreaterThan = gt(aHigh, b.high);
        gtBool aLowGreaterThan = gt(aLow, b.low);

        return mux(
            highEqual,
            mux(aHighGreaterThan, b, a),
            mux(aLowGreaterThan, b, a)
        );
    }

    function mux(gtBool bit, uint256 a, gtUint256 memory b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 aHigh, uint128 aLow) = _splitUint256(a);

        result.low = mux(bit, aLow, b.low);
        result.high = mux(bit, aHigh, b.high);
        
        return result;
    }


    // =========== Operations with RHS_PUBLIC parameter ===========
    // =========== 8 bit operations ==============

    function add(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function checkedAdd(gtUint8 a, uint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint8 a, uint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function sub(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function checkedSub(gtUint8 a, uint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint8 a, uint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function mul(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function checkedMul(gtUint8 a, uint8 b) internal returns (gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b));

        return checkRes8(gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint8 a, uint8 b) internal returns (gtBool, gtUint8) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint8.wrap(res));
    }

    function div(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function rem(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function and(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function or(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function xor(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function shl(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function shr(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function eq(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function ne(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function ge(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function gt(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function le(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function lt(gtUint8 a, uint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function min(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function max(gtUint8 a, uint8 b) internal returns (gtUint8) {
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint8.unwrap(a), uint256(b)));
    }

    function mux(gtBool bit, gtUint8 a, uint8 b) internal returns (gtUint8){
        return gtUint8.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtBool.unwrap(bit), gtUint8.unwrap(a), uint256(b)));
    }

    // =========== 16 bit operations ==============

    function add(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function checkedAdd(gtUint16 a, uint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint16 a, uint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function sub(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function checkedSub(gtUint16 a, uint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint16 a, uint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function mul(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function checkedMul(gtUint16 a, uint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint16 a, uint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function div(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function rem(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function and(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function or(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function xor(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function shl(gtUint16 a, uint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function shr(gtUint16 a, uint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function eq(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function ne(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function ge(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function gt(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function le(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function lt(gtUint16 a, uint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function min(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function max(gtUint16 a, uint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtUint16.unwrap(a), uint256(b)));
    }

    function mux(gtBool bit, gtUint16 a, uint16 b) internal returns (gtUint16){
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.RHS_PUBLIC), gtBool.unwrap(bit), gtUint16.unwrap(a), uint256(b)));
    }


    // =========== 32 bit operations ==============

    function add(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function checkedAdd(gtUint32 a, uint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint32 a, uint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function sub(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function checkedSub(gtUint32 a, uint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint32 a, uint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function mul(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function checkedMul(gtUint32 a, uint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint32 a, uint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function div(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function rem(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function and(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }
    function or(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function xor(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function shl(gtUint32 a, uint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function shr(gtUint32 a, uint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(MPC_PRECOMPILE).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function eq(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function ne(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function ge(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function gt(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function le(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function lt(gtUint32 a, uint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function min(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function max(gtUint32 a, uint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtUint32.unwrap(a), uint256(b)));
    }

    function mux(gtBool bit, gtUint32 a, uint32 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.RHS_PUBLIC), gtBool.unwrap(bit), gtUint32.unwrap(a), uint256(b)));
    }


    // =========== 64 bit operations ==============

    function add(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function checkedAdd(gtUint64 a, uint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint64 a, uint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function sub(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function checkedSub(gtUint64 a, uint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint64 a, uint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function mul(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function checkedMul(gtUint64 a, uint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint64 a, uint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function div(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function rem(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function and(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function or(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function xor(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function shl(gtUint64 a, uint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Shl(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function shr(gtUint64 a, uint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Shr(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function eq(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function ne(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function ge(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function gt(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function le(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function lt(gtUint64 a, uint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function min(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function max(gtUint64 a, uint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtUint64.unwrap(a), uint256(b)));
    }

    function mux(gtBool bit, gtUint64 a, uint64 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.RHS_PUBLIC), gtBool.unwrap(bit), gtUint64.unwrap(a), uint256(b)));
    }

    // =========== 128 bit operations ==============

    function add(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);
        
        // Add low parts
        result.low = add(a.low, bLow);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = add(a.high, bHigh);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, add(result.high, uint64(1)));
        
        return result;
    }

    function checkedAdd(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);
        
        // Add low parts
        result.low = add(a.low, bLow);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = checkedAdd(a.high, bHigh);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, checkedAdd(result.high, uint64(1)));
        
        return result;
    }

    function checkedAddWithOverflowBit(gtUint128 memory a, uint128 b) internal returns (gtBool, gtUint128 memory) {
        gtBool bit = setPublic(false);
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);
        
        // Add low parts
        result.low = add(a.low, bLow);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        (gtBool overflow, gtUint64 high) = checkedAddWithOverflowBit(a.high, bHigh);
        (gtBool overflowWithCarry, gtUint64 highWithCarry) = checkedAddWithOverflowBit(high, uint64(1));

        // Handle carry if needed
        bit = mux(carry, overflow, or(overflow, overflowWithCarry));
        result.high = mux(carry, high, highWithCarry);
        
        return (bit, result);
    }

    function sub(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);
        
        // Subtract low parts
        result.low = sub(a.low, bLow);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, bLow);
        
        // Subtract high parts with borrow if needed
        result.high = sub(a.high, bHigh);
        
        // Subtract borrow from high part if needed
        result.high = mux(borrow, result.high, sub(result.high, uint64(1)));
        
        return result;
    }

    function checkedSub(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);
        
        // Subtract low parts
        result.low = sub(a.low, bLow);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, bLow);
        
        // Subtract high parts with borrow if needed
        result.high = checkedSub(a.high, bHigh);
        
        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            checkedSub(
                mux(borrow, add(result.high, uint64(1)), result.high),
                uint64(1)
            )
        );
        return result;
    }

    function checkedSubWithOverflowBit(gtUint128 memory a, uint128 b) internal returns (gtBool, gtUint128 memory) {
        gtBool bit = setPublic(false);
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);
        
        // Subtract low parts
        result.low = sub(a.low, bLow);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, bLow);
        
        // Subtract high parts with borrow if needed
        (gtBool overflow, gtUint64 high) = checkedSubWithOverflowBit(a.high, bHigh);
        (gtBool overflowWithCarry, gtUint64 highWithCarry) = checkedSubWithOverflowBit(high, uint64(1));

        // Handle borrow if needed
        bit = mux(borrow, overflow, or(overflow, overflowWithCarry));
        result.high = mux(borrow, high, highWithCarry);
        
        return (bit, result);
    }

    function _mul64(gtUint64 a, uint64 b) private returns (gtUint64, gtUint64) {
        uint64 MAX_UINT32 = uint64(type(uint32).max);

        gtUint64 pp0;
        gtUint64 pp1;
        gtUint64 pp2;
        gtUint64 pp3;

        {
            // Split the numbers into 32-bit parts
            gtUint64 aLow = and(a, MAX_UINT32);
            gtUint64 aHigh = shr(a, 32);
            uint64 bLow = b & type(uint32).max;
            uint64 bHigh = b >> 32;

            // Compute partial products
            pp0 = mul(aLow, bLow);
            pp1 = mul(aLow, bHigh);
            pp2 = mul(aHigh, bLow);
            pp3 = mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint64 mid = add(
            add(
                shr(pp0, 32),
                and(pp1, MAX_UINT32)
            ),
            and(pp2, MAX_UINT32)
        );
        gtUint64 carry = shr(mid, 32);

        gtUint64 high = add(
            add(pp3, shr(pp1, 32)),
            add(shr(pp2, 32), carry)
        );
        gtUint64 low = or(
            and(pp0, MAX_UINT32),
            shl(and(mid, MAX_UINT32), 32)
        );

        return (high, low);
    }

    function mul(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        uint64 bLow = uint64(b & type(uint64).max);
        uint64 bHigh = uint64(b >> 64);

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(a.low, bLow);
        (, gtUint64 pp1) = _mul64(a.high, bLow);
        (, gtUint64 pp2) = _mul64(a.low, bHigh);

        // Compute the high and low parts
        result.high = add(
            add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function checkedMul(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        uint64 bLow = uint64(b & type(uint64).max);
        uint64 bHigh = uint64(b >> 64);

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(a.low, bLow);
        (gtUint64 pp2, gtUint64 pp1) = _mul64(a.high, bLow);
        (gtUint64 pp4, gtUint64 pp3) = _mul64(a.low, bHigh);
        (gtUint64 pp6, gtUint64 pp5) = _mul64(a.high, bHigh);

        // Compute the high and low parts
        result.high = checkedAdd(
            checkedAdd(pp0, pp1),
            pp3
        );
        result.low = low;

        // Check for overflow
        checkedSub(
            uint64(0),
            add(
                add(pp2, pp4),
                add(pp5, pp6)
            )
        );
        
        return result;
    }

    function checkedMulWithOverflowBit(gtUint128 memory a, uint128 b) internal returns (gtBool, gtUint128 memory) {
        gtUint128 memory result;

        gtUint64 low;
        gtUint64 pp0;
        gtUint64 pp1;
        gtUint64 pp2;
        gtUint64 pp3;
        gtUint64 pp4;
        gtUint64 pp5;
        gtUint64 pp6;

        {
            uint64 bLow = uint64(b & type(uint64).max);
            uint64 bHigh = uint64(b >> 64);

            // Compute partial products
            (pp0, low) = _mul64(a.low, bLow);
            (pp2, pp1) = _mul64(a.high, bLow);
            (pp4, pp3) = _mul64(a.low, bHigh);
            (pp6, pp5) = _mul64(a.high, bHigh);
        }

        // Compute the high and low parts
        gtBool overflow1;

        (gtBool overflow0, gtUint64 high) = checkedAddWithOverflowBit(pp0, pp1);
        (overflow1, result.high) = checkedAddWithOverflowBit(high, pp3);

        result.low = low;

        // Check for overflow
        gtBool bit = or(
            or(overflow0, overflow1),
            gt(
                add(
                    add(pp2, pp4),
                    add(pp5, pp6)
                ),
                uint64(0)
            )
        );
        
        return (bit, result);
    }

    function and(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        result.low = and(a.low, bLow);
        result.high = and(a.high, bHigh);
        
        return result;
    }

    function or(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        result.low = or(a.low, bLow);
        result.high = or(a.high, bHigh);
        
        return result;
    }

    function xor(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        result.low = xor(a.low, bLow);
        result.high = xor(a.high, bHigh);
        
        return result;
    }

    function shl(gtUint128 memory a, uint8 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        if (b >= 64) {
            shl(a.high, b); // check for overflow in high part

            result.low = setPublic64(0);
            result.high = shl(a.low, b - 64);
        } else if (b > 0) {
            // Mask to clear the bits of the low part that will be shifted out
            uint64 mask = uint64(type(uint64).max >> b);

            result.low = shl(and(a.low, mask), b);

            // Mask to clear the bits of the low part that remain in the low part
            mask = uint64(type(uint64).max << 64 - b);

            result.high = or(shl(a.high, b), shr(and(a.low, mask), 64 - b));
        } else {
            result.low = a.low;
            result.high = a.high;
        }

        return result;
    }

    function shr(gtUint128 memory a, uint8 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        if (b >= 64) {
            shr(a.low, b); // check for overflow in low part

            result.low = shr(a.high, b - 64);
            result.high = setPublic64(0);
        } else if (b > 0) {
            // Mask to clear the bits of the low part that will be shifted out
            uint64 mask = uint64(type(uint64).max >> 64 - b);

            result.low = or(shr(a.low, b), shl(and(a.high, mask), 64 - b));

            // Mask to clear the bits of the low part that remain in the low part
            mask = uint64(type(uint64).max << b);

            result.high = shr(and(a.high, mask), b);
        } else {
            result.low = a.low;
            result.high = a.high;
        }

        return result;
    }

    function eq(gtUint128 memory a, uint128 b) internal returns (gtBool) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        return and(eq(a.low, bLow), eq(a.high, bHigh));
    }

    function ne(gtUint128 memory a, uint128 b) internal returns (gtBool) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        return or(ne(a.low, bLow), ne(a.high, bHigh));
    }

    function ge(gtUint128 memory a, uint128 b) internal returns (gtBool) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, gt(a.high, bHigh), ge(a.low, bLow));
    }

    function gt(gtUint128 memory a, uint128 b) internal returns (gtBool) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, gt(a.high, bHigh), gt(a.low, bLow));
    }

    function le(gtUint128 memory a, uint128 b) internal returns (gtBool) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, lt(a.high, bHigh), le(a.low, bLow));
    }

    function lt(gtUint128 memory a, uint128 b) internal returns (gtBool) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, lt(a.high, bHigh), lt(a.low, bLow));
    }

    function min(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        gtBool highEqual = eq(a.high, bHigh);
        gtBool aHighLessThan = lt(a.high, bHigh);
        gtBool aLowLessThan = lt(a.low, bLow);

        return mux(
            highEqual,
            mux(aHighLessThan, b, a),
            mux(aLowLessThan, b, a)
        );
    }

    function max(gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        gtBool highEqual = eq(a.high, bHigh);
        gtBool aHighGreaterThan = gt(a.high, bHigh);
        gtBool aLowGreaterThan = gt(a.low, bLow);

        return mux(
            highEqual,
            mux(aHighGreaterThan, b, a),
            mux(aLowGreaterThan, b, a)
        );
    }

    function mux(gtBool bit, gtUint128 memory a, uint128 b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        (uint64 bHigh, uint64 bLow) = _splitUint128(b);

        result.low = mux(bit, a.low, bLow);
        result.high = mux(bit, a.high, bHigh);
        
        return result;
    }

    // =========== 256 bit operations ==============

    function add(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);
        
        // Add low parts
        result.low = add(a.low, bLow);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = add(a.high, bHigh);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, add(result.high, uint128(1)));
        
        return result;
    }

    function checkedAdd(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);
        
        // Add low parts
        result.low = add(a.low, bLow);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        result.high = checkedAdd(a.high, bHigh);
        
        // Add carry to high part if needed
        result.high = mux(carry, result.high, checkedAdd(result.high, uint128(1)));
        
        return result;
    }

    function checkedAddWithOverflowBit(gtUint256 memory a, uint256 b) internal returns (gtBool, gtUint256 memory) {
        gtBool bit = setPublic(false);
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);
        
        // Add low parts
        result.low = add(a.low, bLow);
        
        // Check if there's a carry from low addition
        gtBool carry = lt(result.low, a.low);
        
        // Add high parts with carry if needed
        (gtBool overflow, gtUint128 memory high) = checkedAddWithOverflowBit(a.high, bHigh);
        (gtBool overflowWithCarry, gtUint128 memory highWithCarry) = checkedAddWithOverflowBit(high, uint128(1));

        // Handle carry if needed
        bit = mux(carry, overflow, or(overflow, overflowWithCarry));
        result.high = mux(carry, high, highWithCarry);
        
        return (bit, result);
    }

    function sub(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);
        
        // Subtract low parts
        result.low = sub(a.low, bLow);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, bLow);
        
        // Subtract high parts with borrow if needed
        result.high = sub(a.high, bHigh);
        
        // Subtract borrow from high part if needed
        result.high = mux(borrow, result.high, sub(result.high, uint128(1)));
        
        return result;
    }

    function checkedSub(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);
        
        // Subtract low parts
        result.low = sub(a.low, bLow);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, bLow);
        
        // Subtract high parts with borrow if needed
        result.high = checkedSub(a.high, bHigh);
        
        // Subtract borrow from high part if needed
        result.high = mux(
            borrow,
            result.high,
            checkedSub(
                mux(borrow, add(result.high, uint128(1)), result.high),
                uint128(1)
            )
        );
        return result;
    }

    function checkedSubWithOverflowBit(gtUint256 memory a, uint256 b) internal returns (gtBool, gtUint256 memory) {
        gtBool bit = setPublic(false);
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);
        
        // Subtract low parts
        result.low = sub(a.low, bLow);
        
        // Check if there's a borrow from low subtraction
        gtBool borrow = lt(a.low, bLow);
        
        // Subtract high parts with borrow if needed
        (gtBool overflow, gtUint128 memory high) = checkedSubWithOverflowBit(a.high, bHigh);
        (gtBool overflowWithCarry, gtUint128 memory highWithCarry) = checkedSubWithOverflowBit(high, uint128(1));

        // Handle borrow if needed
        bit = mux(borrow, overflow, or(overflow, overflowWithCarry));
        result.high = mux(borrow, high, highWithCarry);
        
        return (bit, result);
    }

    function _mul128(gtUint128 memory a, uint128 b) private returns (gtUint128 memory, gtUint128 memory) {
        uint128 MAX_UINT64 = uint128(type(uint64).max);

        gtUint128 memory pp0;
        gtUint128 memory pp1;
        gtUint128 memory pp2;
        gtUint128 memory pp3;

        {
            // Split the numbers into 64-bit parts
            gtUint128 memory aLow = and(a, MAX_UINT64);
            gtUint128 memory aHigh = shr(a, 64);
            uint128 bLow = b & type(uint64).max;
            uint128 bHigh = b >> 64;

            // Compute partial products
            pp0 = mul(aLow, bLow);
            pp1 = mul(aLow, bHigh);
            pp2 = mul(aHigh, bLow);
            pp3 = mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint128 memory mid = add(
            add(
                shr(pp0, 64),
                and(pp1, MAX_UINT64)
            ),
            and(pp2, MAX_UINT64)
        );
        gtUint128 memory carry = shr(mid, 64);

        gtUint128 memory high = add(
            add(pp3, shr(pp1, 64)),
            add(shr(pp2, 64), carry)
        );
        gtUint128 memory low = or(
            and(pp0, MAX_UINT64),
            shl(and(mid, MAX_UINT64), 64)
        );

        return (high, low);
    }

    function mul(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(a.low, bLow);
        (, gtUint128 memory pp1) = _mul128(a.high, bLow);
        (, gtUint128 memory pp2) = _mul128(a.low, bHigh);

        // Compute the high and low parts
        result.high = add(
            add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function checkedMul(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        // Compute partial products
        (gtUint128 memory pp0, gtUint128 memory low) = _mul128(a.low, bLow);
        (gtUint128 memory pp2, gtUint128 memory pp1) = _mul128(a.high, bLow);
        (gtUint128 memory pp4, gtUint128 memory pp3) = _mul128(a.low, bHigh);
        (gtUint128 memory pp6, gtUint128 memory pp5) = _mul128(a.high, bHigh);

        // Compute the high and low parts
        result.high = checkedAdd(
            checkedAdd(pp0, pp1),
            pp3
        );
        result.low = low;

        // Check for overflow
        checkedSub(
            uint128(0),
            add(
                add(pp2, pp4),
                add(pp5, pp6)
            )
        );
        
        return result;
    }

    function checkedMulWithOverflowBit(gtUint256 memory a, uint256 b) internal returns (gtBool, gtUint256 memory) {
        gtUint256 memory result;

        gtUint128 memory low;
        gtUint128 memory pp0;
        gtUint128 memory pp1;
        gtUint128 memory pp2;
        gtUint128 memory pp3;
        gtUint128 memory pp4;
        gtUint128 memory pp5;
        gtUint128 memory pp6;

        {
            (uint128 bHigh, uint128 bLow) = _splitUint256(b);

            // Compute partial products
            (pp0, low) = _mul128(a.low, bLow);
            (pp2, pp1) = _mul128(a.high, bLow);
            (pp4, pp3) = _mul128(a.low, bHigh);
            (pp6, pp5) = _mul128(a.high, bHigh);
        }

        // Compute the high and low parts
        gtBool overflow1;

        (gtBool overflow0, gtUint128 memory high) = checkedAddWithOverflowBit(pp0, pp1);
        (overflow1, result.high) = checkedAddWithOverflowBit(high, pp3);

        result.low = low;

        // Check for overflow
        gtBool bit = or(
            or(overflow0, overflow1),
            gt(
                add(
                    add(pp2, pp4),
                    add(pp5, pp6)
                ),
                uint128(0)
            )
        );
        
        return (bit, result);
    }

    function and(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        result.low = and(a.low, bLow);
        result.high = and(a.high, bHigh);
        
        return result;
    }

    function or(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        result.low = or(a.low, bLow);
        result.high = or(a.high, bHigh);
        
        return result;
    }

    function xor(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        result.low = xor(a.low, bLow);
        result.high = xor(a.high, bHigh);
        
        return result;
    }

    function shl(gtUint256 memory a, uint8 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        if (b >= 128) {
            shl(a.high, b); // check for overflow in high part

            result.low = setPublic128(0);
            result.high = shl(a.low, b - 128);
        } else if (b > 0) {
            // Mask to clear the bits of the low part that will be shifted out
            uint128 mask = uint128(type(uint128).max >> b);

            result.low = shl(and(a.low, mask), b);

            // Mask to clear the bits of the low part that remain in the low part
            mask = uint128(type(uint128).max << 128 - b);

            result.high = or(shl(a.high, b), shr(and(a.low, mask), 128 - b));
        } else {
            result.low = a.low;
            result.high = a.high;
        }

        return result;
    }

    function shr(gtUint256 memory a, uint8 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        if (b >= 128) {
            shr(a.low, b); // check for overflow in low part

            result.low = shr(a.high, b - 128);
            result.high = setPublic128(0);
        } else if (b > 0) {
            // Mask to clear the bits of the low part that will be shifted out
            uint128 mask = uint128(type(uint128).max >> 128 - b);

            result.low = or(shr(a.low, b), shl(and(a.high, mask), 128 - b));

            // Mask to clear the bits of the low part that remain in the low part
            mask = uint128(type(uint128).max << b);

            result.high = shr(and(a.high, mask), b);
        } else {
            result.low = a.low;
            result.high = a.high;
        }

        return result;
    }

    function eq(gtUint256 memory a, uint256 b) internal returns (gtBool) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        return and(eq(a.low, bLow), eq(a.high, bHigh));
    }

    function ne(gtUint256 memory a, uint256 b) internal returns (gtBool) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        return or(ne(a.low, bLow), ne(a.high, bHigh));
    }

    function ge(gtUint256 memory a, uint256 b) internal returns (gtBool) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, gt(a.high, bHigh), ge(a.low, bLow));
    }

    function gt(gtUint256 memory a, uint256 b) internal returns (gtBool) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, gt(a.high, bHigh), gt(a.low, bLow));
    }

    function le(gtUint256 memory a, uint256 b) internal returns (gtBool) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, lt(a.high, bHigh), le(a.low, bLow));
    }

    function lt(gtUint256 memory a, uint256 b) internal returns (gtBool) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        gtBool highEqual = eq(a.high, bHigh);

        return mux(highEqual, lt(a.high, bHigh), lt(a.low, bLow));
    }

    function min(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        gtBool highEqual = eq(a.high, bHigh);
        gtBool aHighLessThan = lt(a.high, bHigh);
        gtBool aLowLessThan = lt(a.low, bLow);

        return mux(
            highEqual,
            mux(aHighLessThan, b, a),
            mux(aLowLessThan, b, a)
        );
    }

    function max(gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        gtBool highEqual = eq(a.high, bHigh);
        gtBool aHighGreaterThan = gt(a.high, bHigh);
        gtBool aLowGreaterThan = gt(a.low, bLow);

        return mux(
            highEqual,
            mux(aHighGreaterThan, b, a),
            mux(aLowGreaterThan, b, a)
        );
    }

    function mux(gtBool bit, gtUint256 memory a, uint256 b) internal returns (gtUint256 memory) {
        gtUint256 memory result;

        (uint128 bHigh, uint128 bLow) = _splitUint256(b);

        result.low = mux(bit, a.low, bLow);
        result.high = mux(bit, a.high, bHigh);
        
        return result;
    }

    // In the context of a transfer, scalar balances are irrelevant;
    // The only possibility for a scalar value is within the "amount" parameter.
    // Therefore, in this scenario, LHS_PUBLIC signifies a scalar amount, not balance1.

    function transfer(gtUint8 a, gtUint8 b, uint8 amount) internal returns (gtUint8, gtUint8, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint8.wrap(new_a), gtUint8.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint16 b, uint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint16 b, uint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint8 b, uint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint32 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint32 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint32 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, uint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint8.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint16.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint64.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, uint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint32.unwrap(b), uint256(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint8 a, gtUint8 b, uint8 amount, gtUint8 allowance) internal returns (gtUint8, gtUint8, gtBool, gtUint8){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint8.wrap(new_a), gtUint8.wrap(new_b), gtBool.wrap(res), gtUint8.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint16 b, uint16 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint16 b, uint16 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint8 b, uint16 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    // Allowance with 8 bits
    function transferWithAllowance(gtUint16 a, gtUint16 b, uint16 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint16 b, uint16 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint8 b, uint16 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, uint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, uint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, uint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, uint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, uint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // Allowance with 8 bits
    function transferWithAllowance(gtUint32 a, gtUint32 b, uint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, uint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, uint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, uint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, uint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // Allowance with 16 bits
    function transferWithAllowance(gtUint32 a, gtUint32 b, uint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, uint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, uint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, uint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, uint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, uint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 8 bits
    function transferWithAllowance(gtUint64 a, gtUint64 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, uint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 16 bits
    function transferWithAllowance(gtUint64 a, gtUint64 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, uint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 32 bits
    function transferWithAllowance(gtUint64 a, gtUint64 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint8.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint8.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint16.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint16.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint32.unwrap(a), gtUint64.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, uint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.LHS_PUBLIC), gtUint64.unwrap(a), gtUint32.unwrap(b), uint256(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }


    // ================= Cast operation =================
    // =========== 8 - 16 bit operations ==============

    function add(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function add(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedAdd(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedAdd(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint8 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint16 a, gtUint8 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function sub(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function sub(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
        Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedSub(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedSub(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint8 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint16 a, gtUint8 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function mul(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function mul(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedMul(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedMul(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b));

        return checkRes16(gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint8 a, gtUint16 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint16 a, gtUint8 b) internal returns (gtBool, gtUint16) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint16.wrap(res));
    }

    function div(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function div(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function min(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint16 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint8 b) internal returns (gtUint16) {
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint16 b) internal returns (gtUint16){
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint8 b) internal returns (gtUint16){
        return gtUint16.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint16 b, gtUint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint8 b, gtUint16 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint16 b, gtUint8 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint8 b, gtUint8 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint16 b, gtUint8 amount) internal returns (gtUint16, gtUint16, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint16 a, gtUint8 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint16 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint8 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint16 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint16 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint16 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    // Allowance with 16 bit

    function transferWithAllowance(gtUint16 a, gtUint8 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint16 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint8 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint16 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint16 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint16, gtUint16, gtBool, gtUint16){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint16.wrap(new_a), gtUint16.wrap(new_b), gtBool.wrap(res), gtUint16.wrap(new_allowance));
    }


    // =========== 8 - 32 bit operations ==============

    function add(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function add(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedAdd(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAdd(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint8 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint32 a, gtUint8 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function sub(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function sub(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedSub(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSub(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint8 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint32 a, gtUint8 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function mul(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function mul(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedMul(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMul(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint8 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint32 a, gtUint8 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function div(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function div(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function max(gtUint32 a, gtUint8 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint32 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint8 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint32 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T,  MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint32 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T,  MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint32 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint8 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T,  MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint32 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // Allowance with 16 bit
    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // Allowance with 32 bit
    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint8 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint32 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // =========== 16 - 32 bit operations ==============

    function add(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function add(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedAdd(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAdd(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint16 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint32 a, gtUint16 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function sub(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function sub(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedSub(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSub(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint16 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint32 a, gtUint16 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function mul(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function mul(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedMul(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMul(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b));

        return checkRes32(gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint16 a, gtUint32 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint32 a, gtUint16 b) internal returns (gtBool, gtUint32) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint32.wrap(res));
    }

    function div(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function div(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function min(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint32 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function max(gtUint32 a, gtUint16 b) internal returns (gtUint32) {
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint32 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint16 b) internal returns (gtUint32){
        return gtUint32.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint16.unwrap(b)));
    }

    function transfer(gtUint16 a, gtUint32 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, gtUint32 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint32 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, gtUint8 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint32 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint16 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint32 b, gtUint16 amount) internal returns (gtUint32, gtUint32, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T,  MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // Allowance with 16 bit
    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    // Allowance with 32 bit
    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint32 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint16 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint32 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint32, gtUint32, gtBool, gtUint32){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint32.wrap(new_a), gtUint32.wrap(new_b), gtBool.wrap(res), gtUint32.wrap(new_allowance));
    }


    // =========== 8 - 64 bit operations ==============

    function add(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function add(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedAdd(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAdd(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint8 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint64 a, gtUint8 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function sub(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedSub(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSub(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint8 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint64 a, gtUint8 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function mul(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function checkedMul(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMul(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint8 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint64 a, gtUint8 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function div(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function rem(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function and(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function or(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function xor(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function eq(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function ne(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function ge(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function gt(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function gt(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function le(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function le(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function lt(gtUint8 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint8 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function min(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function max(gtUint8 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function max(gtUint64 a, gtUint8 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function mux(gtBool bit, gtUint8 a, gtUint64 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint8.unwrap(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint8 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint8.unwrap(b)));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint8 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint8 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 16 bit
    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 32 bit
    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 64 bit
    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint8 a, gtUint64 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint8.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint8 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint8.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }



    // =========== 16 - 64 bit operations ==============

    function add(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function add(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedAdd(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAdd(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint16 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint64 a, gtUint16 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function sub(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedSub(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSub(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint16 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint64 a, gtUint16 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function mul(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function checkedMul(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMul(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint16 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint64 a, gtUint16 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function div(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function rem(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function and(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function or(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function xor(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function eq(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function ne(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function ge(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function gt(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function gt(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function le(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function le(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function lt(gtUint16 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint16 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function min(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function max(gtUint16 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function max(gtUint64 a, gtUint16 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function mux(gtBool bit, gtUint16 a, gtUint64 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint16.unwrap(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint16 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint16.unwrap(b)));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint16 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint16 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 16 bit
    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 32 bit
    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 64 bit
    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint16 a, gtUint64 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint16.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint16 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint16.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }



    // =========== 32 - 64 bit operations ==============

    function add(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function add(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Add(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function checkedAdd(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAdd(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint32 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedAddWithOverflowBit(gtUint64 a, gtUint32 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedAdd(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function sub(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function sub(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Sub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function checkedSub(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSub(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint32 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedSubWithOverflowBit(gtUint64 a, gtUint32 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedSub(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function mul(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function mul(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function checkedMul(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMul(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b));

        return checkRes64(gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint32 a, gtUint64 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function checkedMulWithOverflowBit(gtUint64 a, gtUint32 b) internal returns (gtBool, gtUint64) {
        (uint256 bit, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            CheckedMul(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b));

        return (gtBool.wrap(bit), gtUint64.wrap(res));
    }

    function div(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function div(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Div(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function rem(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function rem(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Rem(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function and(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function and(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            And(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function or(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function or(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Or(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function xor(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function xor(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Xor(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function eq(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function eq(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Eq(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function ne(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function ne(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ne(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function ge(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function ge(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Ge(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function gt(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function gt(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Gt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function le(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function le(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Le(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function lt(gtUint32 a, gtUint64 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function lt(gtUint64 a, gtUint32 b) internal returns (gtBool) {
        return gtBool.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Lt(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function min(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function min(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Min(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function max(gtUint32 a, gtUint64 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function max(gtUint64 a, gtUint32 b) internal returns (gtUint64) {
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Max(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function mux(gtBool bit, gtUint32 a, gtUint64 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint32.unwrap(a), gtUint64.unwrap(b)));
    }

    function mux(gtBool bit, gtUint64 a, gtUint32 b) internal returns (gtUint64){
        return gtUint64.wrap(ExtendedOperations(address(MPC_PRECOMPILE)).
            Mux(combineEnumsToBytes3(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtBool.unwrap(bit), gtUint64.unwrap(a), gtUint32.unwrap(b)));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint64 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint64.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint8 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint16 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint32 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint32 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transfer(gtUint64 a, gtUint64 b, gtUint32 amount) internal returns (gtUint64, gtUint64, gtBool){
        (uint256 new_a, uint256 new_b, uint256 res) = ExtendedOperations(address(MPC_PRECOMPILE)).
            Transfer(combineEnumsToBytes4(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET), gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint8 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint16 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint64 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint64.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint32 amount, gtUint8 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint8.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 16 bit
    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint8 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint16 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint64 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint64.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint32 amount, gtUint16 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint16.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 32 bit
    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint8 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint16 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint64 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint64.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint32 amount, gtUint32 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint32.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    // Allowance with 64 bit
    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint8 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT8_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint8.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint16 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT16_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint16.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint32 a, gtUint64 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint32.unwrap(a), gtUint64.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint32 b, gtUint64 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint32.unwrap(b), gtUint64.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }

    function transferWithAllowance(gtUint64 a, gtUint64 b, gtUint32 amount, gtUint64 allowance) internal returns (gtUint64, gtUint64, gtBool, gtUint64){
        (uint256 new_a, uint256 new_b, uint256 res, uint256 new_allowance) = ExtendedOperations(address(MPC_PRECOMPILE)).
            TransferWithAllowance(combineEnumsToBytes5(MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT64_T, MPC_TYPE.SUINT32_T, MPC_TYPE.SUINT64_T, ARGS.BOTH_SECRET),
            gtUint64.unwrap(a), gtUint64.unwrap(b), gtUint32.unwrap(amount), gtUint64.unwrap(allowance));
        return (gtUint64.wrap(new_a), gtUint64.wrap(new_b), gtBool.wrap(res), gtUint64.wrap(new_allowance));
    }
}