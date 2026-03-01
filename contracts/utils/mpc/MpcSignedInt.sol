// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./MpcInterface.sol";
import "./MpcTypes.sol";
import { MpcCore } from "./MpcCore.sol";

library MpcSignedInt {
    // =========== signed 8 bit operations ==============

    function validateCiphertext(itInt8 memory input) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    ctInt8.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt8 ct) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    ctInt8.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt8 pt) internal returns (ctInt8) {
        return
            ctInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    gtInt8.unwrap(pt)
                )
            );
    }

    function offBoardToUser(gtInt8 pt, address addr) internal returns (ctInt8) {
        return
            ctInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    gtInt8.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt8 pt,
        address addr
    ) internal returns (utInt8 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic8(int8 pt) internal returns (gtInt8) {
        // Simple approach: reinterpret the bits directly
        uint8 unsignedBits;
        assembly {
            unsignedBits := pt
        }
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT8_T)),
                    uint256(unsignedBits)
                )
            );
    }

    function add(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function sub(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function mul(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function div(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        // Explicit division by zero check
        require(MpcCore.decrypt(ne(b, setPublic8(0))), "division by zero");
        // Check if numbers are negative by testing the sign bit (bit 63 for int64)
        gtBool aNegative = eq(
            and(a, setPublic8(int8(type(int8).min))),
            setPublic8(int8(type(int8).min))
        );

        gtBool bNegative = eq(
            and(b, setPublic8(int8(type(int8).min))),
            setPublic8(int8(type(int8).min))
        );

        // Get absolute values: if negative, use two's complement negation
        gtInt8 aAbs = mux(
            aNegative,
            a,
            sub(setPublic8(int8(0)), a) // 0 - a
        );

        gtInt8 bAbs = mux(
            bNegative,
            b,
            sub(setPublic8(int8(0)), b) // 0 - b
        );

        // Perform unsigned division on absolute values
        gtUint8 unsignedResult = MpcCore.div(gtUint8.wrap(gtInt8.unwrap(aAbs)), gtUint8.wrap(gtInt8.unwrap(bAbs)));

    
        // Result is negative if exactly one operand is negative
        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);

        gtInt8 result = gtInt8.wrap(gtUint8.unwrap(unsignedResult));
    
        // Apply sign: if result should be negative, negate it
        return
            mux(
                resultNegative,
                result,
                sub(setPublic8(int8(0)), result) // 0 - result
            );
    }

    function and(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function or(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function xor(gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function eq(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function ne(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function gt(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtUint8 aU = gtUint8.wrap(gtInt8.unwrap(a));
        gtUint8 bU = gtUint8.wrap(gtInt8.unwrap(b));
        gtUint8 signA = MpcCore.shr(aU, 7);
        gtUint8 signB = MpcCore.shr(bU, 7);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic8(uint8(1))), MpcCore.eq(signB, MpcCore.setPublic8(uint8(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic8(uint8(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtUint8 aU = gtUint8.wrap(gtInt8.unwrap(a));
        gtUint8 bU = gtUint8.wrap(gtInt8.unwrap(b));
        gtUint8 signA = MpcCore.shr(aU, 7);
        gtUint8 signB = MpcCore.shr(bU, 7);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic8(uint8(1))), MpcCore.eq(signB, MpcCore.setPublic8(uint8(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic8(uint8(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function le(gtInt8 a, gtInt8 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt8 ct) internal returns (int8) {
        return
            int8(
                uint8(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT8_T)),
                        gtInt8.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt8 a, gtInt8 b) internal returns (gtInt8) {
        return
            gtInt8.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT8_T,
                        MPC_TYPE.SUINT8_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt8.unwrap(a),
                    gtInt8.unwrap(b)
                )
            );
    }

    function shl(gtInt8 a, uint8 b) internal returns (gtInt8) {
        gtUint8 unsignedResult = MpcCore.shl(gtUint8.wrap(gtInt8.unwrap(a)), b);
        return gtInt8.wrap(gtUint8.unwrap(unsignedResult));
    }
    
    function shr(gtInt8 a, uint8 b) internal returns (gtInt8) {
        gtUint8 value = gtUint8.wrap(gtInt8.unwrap(a));
        gtUint8 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 7), MpcCore.setPublic8(uint8(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint8 mask = uint8(type(uint8).max << (8 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic8(mask));
            }
        }
        return gtInt8.wrap(gtUint8.unwrap(shifted));
    }

    // =========== signed 16 bit operations ==============

    function validateCiphertext(
        itInt16 memory input
    ) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    ctInt16.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt16 ct) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    ctInt16.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt16 pt) internal returns (ctInt16) {
        return
            ctInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    gtInt16.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt16 pt,
        address addr
    ) internal returns (ctInt16) {
        return
            ctInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    gtInt16.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt16 pt,
        address addr
    ) internal returns (utInt16 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic16(int16 pt) internal returns (gtInt16) {
        // Simple approach: reinterpret the bits directly
        uint16 unsignedBits;
        assembly {
            unsignedBits := pt
        }
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT16_T)),
                    uint256(unsignedBits)
                )
            );
    }

    function add(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function sub(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function mul(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function div(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        require(MpcCore.decrypt(ne(b, setPublic16(0))), "division by zero");
        gtBool aNegative = eq(
            and(a, setPublic16(int16(type(int16).min))),
            setPublic16(int16(type(int16).min))
        );

        gtBool bNegative = eq(
            and(b, setPublic16(int16(type(int16).min))),
            setPublic16(int16(type(int16).min))
        );

        gtInt16 aAbs = mux(
            aNegative,
            a,
            sub(setPublic16(int16(0)), a)
        );

        gtInt16 bAbs = mux(
            bNegative,
            b,
            sub(setPublic16(int16(0)), b)
        );

        gtUint16 unsignedResult = MpcCore.div(gtUint16.wrap(gtInt16.unwrap(aAbs)), gtUint16.wrap(gtInt16.unwrap(bAbs)));

        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);
        gtInt16 result = gtInt16.wrap(gtUint16.unwrap(unsignedResult));

        return mux(
            resultNegative,
            result,
            sub(setPublic16(int16(0)), result)
        );
    }

    function and(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function or(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function xor(gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function eq(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function ne(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function gt(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtUint16 aU = gtUint16.wrap(gtInt16.unwrap(a));
        gtUint16 bU = gtUint16.wrap(gtInt16.unwrap(b));
        gtUint16 signA = MpcCore.shr(aU, 15);
        gtUint16 signB = MpcCore.shr(bU, 15);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic16(uint16(1))), MpcCore.eq(signB, MpcCore.setPublic16(uint16(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic16(uint16(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtUint16 aU = gtUint16.wrap(gtInt16.unwrap(a));
        gtUint16 bU = gtUint16.wrap(gtInt16.unwrap(b));
        gtUint16 signA = MpcCore.shr(aU, 15);
        gtUint16 signB = MpcCore.shr(bU, 15);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic16(uint16(1))), MpcCore.eq(signB, MpcCore.setPublic16(uint16(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic16(uint16(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function le(gtInt16 a, gtInt16 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt16 ct) internal returns (int16) {
        return
            int16(
                uint16(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT16_T)),
                        gtInt16.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt16 a, gtInt16 b) internal returns (gtInt16) {
        return
            gtInt16.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT16_T,
                        MPC_TYPE.SUINT16_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt16.unwrap(a),
                    gtInt16.unwrap(b)
                )
            );
    }

    function shl(gtInt16 a, uint8 b) internal returns (gtInt16) {
        gtUint16 unsignedResult = MpcCore.shl(gtUint16.wrap(gtInt16.unwrap(a)), b);
        return gtInt16.wrap(gtUint16.unwrap(unsignedResult));
    }
    
    function shr(gtInt16 a, uint8 b) internal returns (gtInt16) {
        gtUint16 value = gtUint16.wrap(gtInt16.unwrap(a));
        gtUint16 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 15), MpcCore.setPublic16(uint16(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint16 mask = uint16(type(uint16).max << (16 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic16(mask));
            }
        }
        return gtInt16.wrap(gtUint16.unwrap(shifted));
    }

    // =========== signed 32 bit operations ==============

    function validateCiphertext(
        itInt32 memory input
    ) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    ctInt32.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt32 ct) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    ctInt32.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt32 pt) internal returns (ctInt32) {
        return
            ctInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    gtInt32.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt32 pt,
        address addr
    ) internal returns (ctInt32) {
        return
            ctInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    gtInt32.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt32 pt,
        address addr
    ) internal returns (utInt32 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic32(int32 pt) internal returns (gtInt32) {
        // Simple approach: reinterpret the bits directly
        uint32 unsignedBits;
        assembly {
            unsignedBits := pt
        }
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT32_T)),
                    uint256(unsignedBits)
                )
            );
    }

    function add(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function sub(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function mul(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function div(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        require(MpcCore.decrypt(ne(b, setPublic32(0))), "division by zero");
        gtBool aNegative = eq(
            and(a, setPublic32(int32(type(int32).min))),
            setPublic32(int32(type(int32).min))
        );

        gtBool bNegative = eq(
            and(b, setPublic32(int32(type(int32).min))),
            setPublic32(int32(type(int32).min))
        );

        gtInt32 aAbs = mux(
            aNegative,
            a,
            sub(setPublic32(int32(0)), a)
        );

        gtInt32 bAbs = mux(
            bNegative,
            b,
            sub(setPublic32(int32(0)), b)
        );

        gtUint32 unsignedResult = MpcCore.div(gtUint32.wrap(gtInt32.unwrap(aAbs)), gtUint32.wrap(gtInt32.unwrap(bAbs)));

        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);
        gtInt32 result = gtInt32.wrap(gtUint32.unwrap(unsignedResult));

        return mux(
            resultNegative,
            result,
            sub(setPublic32(int32(0)), result)
        );
    }

    function and(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function or(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function xor(gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function eq(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function ne(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function gt(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtUint32 aU = gtUint32.wrap(gtInt32.unwrap(a));
        gtUint32 bU = gtUint32.wrap(gtInt32.unwrap(b));
        gtUint32 signA = MpcCore.shr(aU, 31);
        gtUint32 signB = MpcCore.shr(bU, 31);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic32(uint32(1))), MpcCore.eq(signB, MpcCore.setPublic32(uint32(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic32(uint32(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtUint32 aU = gtUint32.wrap(gtInt32.unwrap(a));
        gtUint32 bU = gtUint32.wrap(gtInt32.unwrap(b));
        gtUint32 signA = MpcCore.shr(aU, 31);
        gtUint32 signB = MpcCore.shr(bU, 31);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic32(uint32(1))), MpcCore.eq(signB, MpcCore.setPublic32(uint32(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic32(uint32(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function le(gtInt32 a, gtInt32 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt32 ct) internal returns (int32) {
        return
            int32(
                uint32(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT32_T)),
                        gtInt32.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt32 a, gtInt32 b) internal returns (gtInt32) {
        return
            gtInt32.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT32_T,
                        MPC_TYPE.SUINT32_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt32.unwrap(a),
                    gtInt32.unwrap(b)
                )
            );
    }

    function shl(gtInt32 a, uint8 b) internal returns (gtInt32) {
        gtUint32 unsignedResult = MpcCore.shl(gtUint32.wrap(gtInt32.unwrap(a)), b);
        return gtInt32.wrap(gtUint32.unwrap(unsignedResult));
    }

    function shr(gtInt32 a, uint8 b) internal returns (gtInt32) {
        gtUint32 value = gtUint32.wrap(gtInt32.unwrap(a));
        gtUint32 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 31), MpcCore.setPublic32(uint32(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint32 mask = uint32(type(uint32).max << (32 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic32(mask));
            }
        }
        return gtInt32.wrap(gtUint32.unwrap(shifted));
    }

    // =========== signed 64 bit operations ==============

    function validateCiphertext(
        itInt64 memory input
    ) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    ctInt64.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt64 ct) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    ctInt64.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt64 pt) internal returns (ctInt64) {
        return
            ctInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    gtInt64.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt64 pt,
        address addr
    ) internal returns (ctInt64) {
        return
            ctInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    gtInt64.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt64 pt,
        address addr
    ) internal returns (utInt64 memory ut) {
        ut.ciphertext = offBoard(pt);
        ut.userCiphertext = offBoardToUser(pt, addr);
    }

    function setPublic64(int64 pt) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT64_T)),
                    uint256(uint64(uint256(int256(pt))))
                )
            );
    }

    function add(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function sub(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function mul(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mul(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function div(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        require(MpcCore.decrypt(ne(b, setPublic64(0))), "division by zero");
        gtBool aNegative = eq(
            and(a, setPublic64(int64(type(int64).min))),
            setPublic64(int64(type(int64).min))
        );

        gtBool bNegative = eq(
            and(b, setPublic64(int64(type(int64).min))),
            setPublic64(int64(type(int64).min))
        );

        gtInt64 aAbs = mux(
            aNegative,
            a,
            sub(setPublic64(int64(0)), a)
        );

        gtInt64 bAbs = mux(
            bNegative,
            b,
            sub(setPublic64(int64(0)), b)
        );

        gtUint64 unsignedResult = MpcCore.div(gtUint64.wrap(gtInt64.unwrap(aAbs)), gtUint64.wrap(gtInt64.unwrap(bAbs)));

        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);
        gtInt64 result = gtInt64.wrap(gtUint64.unwrap(unsignedResult));

        return mux(
            resultNegative,
            result,
            sub(setPublic64(int64(0)), result)
        );
    }

    function and(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function or(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function xor(gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function eq(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function ne(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function gt(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtUint64 aU = gtUint64.wrap(gtInt64.unwrap(a));
        gtUint64 bU = gtUint64.wrap(gtInt64.unwrap(b));
        gtUint64 signA = MpcCore.shr(aU, 63);
        gtUint64 signB = MpcCore.shr(bU, 63);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic64(uint64(1))), MpcCore.eq(signB, MpcCore.setPublic64(uint64(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic64(uint64(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtUint64 aU = gtUint64.wrap(gtInt64.unwrap(a));
        gtUint64 bU = gtUint64.wrap(gtInt64.unwrap(b));
        gtUint64 signA = MpcCore.shr(aU, 63);
        gtUint64 signB = MpcCore.shr(bU, 63);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic64(uint64(1))), MpcCore.eq(signB, MpcCore.setPublic64(uint64(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic64(uint64(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }
    
    function le(gtInt64 a, gtInt64 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt64 ct) internal returns (int64) {
        return
            int64(
                uint64(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT64_T)),
                        gtInt64.unwrap(ct)
                    )
                )
            );
    }

    function mux(gtBool bit, gtInt64 a, gtInt64 b) internal returns (gtInt64) {
        return
            gtInt64.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT64_T,
                        MPC_TYPE.SUINT64_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt64.unwrap(a),
                    gtInt64.unwrap(b)
                )
            );
    }

    function shl(gtInt64 a, uint8 b) internal returns (gtInt64) {
        gtUint64 unsignedResult = MpcCore.shl(gtUint64.wrap(gtInt64.unwrap(a)), b);
        return gtInt64.wrap(gtUint64.unwrap(unsignedResult));
    }

    function shr(gtInt64 a, uint8 b) internal returns (gtInt64) {
        gtUint64 value = gtUint64.wrap(gtInt64.unwrap(a));
        gtUint64 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 63), MpcCore.setPublic64(uint64(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint64 mask = uint64(type(uint64).max << (64 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic64(mask));
            }
        }
        return gtInt64.wrap(gtUint64.unwrap(shifted));
    }

    // =========== signed 128 bit operations ==============

    function validateCiphertext(
        itInt128 memory input
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                    bytes1(uint8(MPC_TYPE.SUINT128_T)),
                    ctInt128.unwrap(input.ciphertext),
                    input.signature
                )
            );
    }

    function onBoard(ctInt128 ct) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                    bytes1(uint8(MPC_TYPE.SUINT128_T)),
                    ctInt128.unwrap(ct)
                )
            );
    }

    function offBoard(gtInt128 pt) internal returns (ctInt128) {
        return
            ctInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard(
                    bytes1(uint8(MPC_TYPE.SUINT128_T)),
                    gtInt128.unwrap(pt)
                )
            );
    }

    function offBoardToUser(
        gtInt128 pt,
        address addr
    ) internal returns (ctInt128) {
               return
            ctInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser(
                    bytes1(uint8(MPC_TYPE.SUINT128_T)),
                    gtInt128.unwrap(pt),
                    abi.encodePacked(addr)
                )
            );
    }

    function offBoardCombined(
        gtInt128 pt,
        address addr
    ) internal returns (utInt128 memory) {
        utInt128 memory result;

        result.ciphertext = offBoard(pt);
        result.userCiphertext = offBoardToUser(pt, addr);

        return result;
    }

    // Helper to reinterpret int64 as uint64 (preserve bits)
    function int64ToUint64(int64 x) internal pure returns (uint64) {
        return uint64(uint256(uint64(x)));
    }
    // Helper to reinterpret uint64 as int64 (preserve bits)
    function uint64ToInt64(uint64 x) internal pure returns (int64) {
        return int64(uint64(uint256(x)));
    }

    function setPublic128(int128 pt) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT128_T)),
                    uint256(uint128(pt))
                )
            );
    }

    function add(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function sub(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function mul(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        // Determine if a and b are negative (check sign bit)
        gtUint128 aU = gtUint128.wrap(gtInt128.unwrap(a));
        gtUint128 bU = gtUint128.wrap(gtInt128.unwrap(b));
        
        gtBool aNegative = MpcCore.eq(MpcCore.shr(aU, 127), MpcCore.setPublic128(uint128(1)));
        gtBool bNegative = MpcCore.eq(MpcCore.shr(bU, 127), MpcCore.setPublic128(uint128(1)));

        // Get absolute values
        gtInt128 aAbs = mux(aNegative, negate(a), a);
        gtInt128 bAbs = mux(bNegative, negate(b), b);

        // Convert to unsigned for multiplication
        gtUint128 aAbsU = gtUint128.wrap(gtInt128.unwrap(aAbs));
        gtUint128 bAbsU = gtUint128.wrap(gtInt128.unwrap(bAbs));

        // Use unsigned 128-bit multiplication
        gtUint128 unsignedResultU = MpcCore.mul(aAbsU, bAbsU);

        // Convert back to signed
        gtInt128 unsignedResult = gtInt128.wrap(gtUint128.unwrap(unsignedResultU));

        // Result is negative if exactly one operand is negative
        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);

        // Apply sign
        return mux(resultNegative, unsignedResult, negate(unsignedResult));
    }

    function div(gtInt128 a, gtInt128 b) internal returns (gtInt128) {
        int128 aValue = decrypt(a);
        int128 bValue = decrypt(b);
        if (bValue == 0) {
            revert("division by zero");
        }
        
        // Handle the overflow case: MIN / -1 = -MIN, but -MIN overflows
        // In 2's complement, this wraps around to MIN itself
        if (aValue == type(int128).min && bValue == -1) {
            return setPublic128(type(int128).min);
        }
        
        int128 resultValue = aValue / bValue;
        return setPublic128(resultValue);
    }

    function negate(gtInt128 a) internal returns (gtInt128) {
        // Two's complement negation: ~a + 1
        gtInt128 inverted = xor(a, setPublic128(int128(-1)));
        return add(inverted, setPublic128(int128(1)));
    }

    function and(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function or(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function xor(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function eq(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function ne(
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function ge(gtInt128 a, gtInt128 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isGt, isEq);
    }

    function gt(gtInt128 a, gtInt128 b) internal returns (gtBool) {
        gtUint128 aU = gtUint128.wrap(gtInt128.unwrap(a));
        gtUint128 bU = gtUint128.wrap(gtInt128.unwrap(b));
        gtUint128 signA = MpcCore.shr(aU, 127);
        gtUint128 signB = MpcCore.shr(bU, 127);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic128(uint128(1))), MpcCore.eq(signB, MpcCore.setPublic128(uint128(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic128(uint128(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt128 a, gtInt128 b) internal returns (gtBool) {
        gtUint128 aU = gtUint128.wrap(gtInt128.unwrap(a));
        gtUint128 bU = gtUint128.wrap(gtInt128.unwrap(b));
        gtUint128 signA = MpcCore.shr(aU, 127);
        gtUint128 signB = MpcCore.shr(bU, 127);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic128(uint128(1))), MpcCore.eq(signB, MpcCore.setPublic128(uint128(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic128(uint128(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function le(gtInt128 a, gtInt128 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        gtBool isEq = eq(a, b);
        return MpcCore.or(isLt, isEq);
    }

    function decrypt(gtInt128 ct) internal returns (int128) {
        return
            int128(
                uint128(
                    ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                        bytes1(uint8(MPC_TYPE.SUINT128_T)),
                        gtInt128.unwrap(ct)
                    )
                )
            );
    }

    function mux(
        gtBool bit,
        gtInt128 a,
        gtInt128 b
    ) internal returns (gtInt128) {
        return
            gtInt128.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT128_T,
                        MPC_TYPE.SUINT128_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt128.unwrap(a),
                    gtInt128.unwrap(b)
                )
            );
    }

    function shl(gtInt128 a, uint8 b) internal returns (gtInt128) {
        gtUint128 unsignedResult = MpcCore.shl(gtUint128.wrap(gtInt128.unwrap(a)), b);
        return gtInt128.wrap(gtUint128.unwrap(unsignedResult));
    }
    
    function shr(gtInt128 a, uint8 b) internal returns (gtInt128) {
        gtUint128 value = gtUint128.wrap(gtInt128.unwrap(a));
        gtUint128 shifted = MpcCore.shr(value, b);
        gtBool sign = MpcCore.eq(MpcCore.shr(value, 127), MpcCore.setPublic128(uint128(1)));
        if (b > 0) {
            if (MpcCore.decrypt(MpcCore.eq(sign, gtBool.wrap(1)))) {
                uint128 mask = uint128(type(uint128).max << (128 - b));
                shifted = MpcCore.or(shifted, MpcCore.setPublic128(mask));
            }
        }
        return gtInt128.wrap(gtUint128.unwrap(shifted));
    } 

    // =========== signed 256 bit operations ==============

    function validateCiphertext(
        itInt256 memory input
    ) internal returns (gtInt256) {
        return gtInt256.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).ValidateCiphertext(
                bytes1(uint8(MPC_TYPE.SUINT256_T)),
                ctInt128.unwrap(input.ciphertext.ciphertextHigh),
                ctInt128.unwrap(input.ciphertext.ciphertextLow),
                input.signature
            )
        );
    }

    function onBoard(ctInt256 memory ct) internal returns (gtInt256) {
        return gtInt256.wrap(
            ExtendedOperations(address(MPC_PRECOMPILE)).OnBoard(
                bytes1(uint8(MPC_TYPE.SUINT256_T)),
                ctInt128.unwrap(ct.ciphertextHigh),
                ctInt128.unwrap(ct.ciphertextLow)
            )
        );
    }

    function offBoard(gtInt256 pt) internal returns (ctInt256 memory) {
        ctInt256 memory result;

        (uint256 ctHigh, uint256 ctLow) = ExtendedOperations(address(MPC_PRECOMPILE)).OffBoard256(
            bytes1(uint8(MPC_TYPE.SUINT256_T)),
            gtInt256.unwrap(pt)
        );
        result = ctInt256({ciphertextHigh: ctInt128.wrap(ctHigh), ciphertextLow: ctInt128.wrap(ctLow)});

        return result;
    }

    function offBoardToUser(
        gtInt256 pt,
        address addr
    ) internal returns (ctInt256 memory) {
        ctInt256 memory result;

        (uint256 ctHigh, uint256 ctLow) = ExtendedOperations(address(MPC_PRECOMPILE)).OffBoardToUser256(
            bytes1(uint8(MPC_TYPE.SUINT256_T)),
            gtInt256.unwrap(pt),
            abi.encodePacked(addr)
        );
        result = ctInt256({ciphertextHigh: ctInt128.wrap(ctHigh), ciphertextLow: ctInt128.wrap(ctLow)});

        return result;
    }

    function offBoardCombined(
        gtInt256 pt,
        address addr
    ) internal returns (utInt256 memory) {
        utInt256 memory result;

        result.ciphertext = offBoard(pt);
        result.userCiphertext = offBoardToUser(pt, addr);

        return result;
    }

    function setPublic256(int256 pt) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).SetPublic(
                    bytes1(uint8(MPC_TYPE.SUINT256_T)),
                    uint256(pt)
                )
            );
    }

    function decrypt(gtInt256 ct) internal returns (int256) {
        return
            int256(
                ExtendedOperations(address(MPC_PRECOMPILE)).Decrypt(
                    bytes1(uint8(MPC_TYPE.SUINT256_T)),
                    gtInt256.unwrap(ct)
                )
            );
    }

    function mux(
        gtBool bit,
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Mux(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtBool.unwrap(bit),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function negate(gtInt256 a) internal returns (gtInt256) {
        // Two's complement negation: ~a + 1
        gtInt256 inverted = xor(a, setPublic256(int256(-1)));
        return add(inverted, setPublic256(int256(1)));
    }

    function add(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Add(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function sub(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Sub(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function mul(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        // Determine if a and b are negative (check sign bit)
        gtUint256 aU = gtUint256.wrap(gtInt256.unwrap(a));
        gtUint256 bU = gtUint256.wrap(gtInt256.unwrap(b));
        
        gtBool aNegative = MpcCore.eq(MpcCore.shr(aU, 255), MpcCore.setPublic256(uint256(1)));
        gtBool bNegative = MpcCore.eq(MpcCore.shr(bU, 255), MpcCore.setPublic256(uint256(1)));

        // Get absolute values
        gtInt256 aAbs = mux(aNegative, negate(a), a);
        gtInt256 bAbs = mux(bNegative, negate(b), b);

        // Convert to unsigned for multiplication
        gtUint256 aAbsU = gtUint256.wrap(gtInt256.unwrap(aAbs));
        gtUint256 bAbsU = gtUint256.wrap(gtInt256.unwrap(bAbs));

        // Use unsigned 256-bit multiplication
        gtUint256 unsignedResultU = MpcCore.mul(aAbsU, bAbsU);

        // Convert back to signed
        gtInt256 unsignedResult = gtInt256.wrap(gtUint256.unwrap(unsignedResultU));

        // Result is negative if exactly one operand is negative
        gtBool resultNegative = MpcCore.xor(aNegative, bNegative);

        // Apply sign
        return mux(resultNegative, unsignedResult, negate(unsignedResult));
    }

    function div(gtInt256 a, gtInt256 b) internal returns (gtInt256) {
        int256 aValue = decrypt(a);
        int256 bValue = decrypt(b);
        if (bValue == 0) {
            revert("division by zero");
        }
        if (aValue == type(int256).min && bValue == -1) {
            return setPublic256(type(int256).min);
        }
        int256 resultValue = aValue / bValue;
        return setPublic256(resultValue);
    }

    function and(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).And(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function or(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Or(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function xor(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtInt256) {
        return
            gtInt256.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Xor(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function eq(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Eq(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function ne(
        gtInt256 a,
        gtInt256 b
    ) internal returns (gtBool) {
        return
            gtBool.wrap(
                ExtendedOperations(address(MPC_PRECOMPILE)).Ne(
                    combineEnumsToBytes3(
                        MPC_TYPE.SUINT256_T,
                        MPC_TYPE.SUINT256_T,
                        ARGS.BOTH_SECRET
                    ),
                    gtInt256.unwrap(a),
                    gtInt256.unwrap(b)
                )
            );
    }

    function gt(gtInt256 a, gtInt256 b) internal returns (gtBool) {
        gtUint256 aU = gtUint256.wrap(gtInt256.unwrap(a));
        gtUint256 bU = gtUint256.wrap(gtInt256.unwrap(b));
        gtUint256 signA = MpcCore.shr(aU, 255);
        gtUint256 signB = MpcCore.shr(bU, 255);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic256(uint256(1))), MpcCore.eq(signB, MpcCore.setPublic256(uint256(1))));
        gtBool aPos_bNeg = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic256(uint256(0))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedGt = MpcCore.gt(aU, bU);
        return MpcCore.or(aPos_bNeg, MpcCore.and(sameSign, unsignedGt));
    }

    function lt(gtInt256 a, gtInt256 b) internal returns (gtBool) {
        gtUint256 aU = gtUint256.wrap(gtInt256.unwrap(a));
        gtUint256 bU = gtUint256.wrap(gtInt256.unwrap(b));
        gtUint256 signA = MpcCore.shr(aU, 255);
        gtUint256 signB = MpcCore.shr(bU, 255);
        gtBool signDiff = MpcCore.ne(MpcCore.eq(signA, MpcCore.setPublic256(uint256(1))), MpcCore.eq(signB, MpcCore.setPublic256(uint256(1))));
        gtBool aNeg_bPos = MpcCore.and(signDiff, MpcCore.eq(signA, MpcCore.setPublic256(uint256(1))));
        gtBool sameSign = MpcCore.eq(signA, signB);
        gtBool unsignedLt = MpcCore.lt(aU, bU);
        return MpcCore.or(aNeg_bPos, MpcCore.and(sameSign, unsignedLt));
    }

    function ge(gtInt256 a, gtInt256 b) internal returns (gtBool) {
        gtBool isLt = lt(a, b);
        return MpcCore.not(isLt);
    }

    function le(gtInt256 a, gtInt256 b) internal returns (gtBool) {
        gtBool isGt = gt(a, b);
        return MpcCore.not(isGt);
    }

    // Helper to convert gtInt128 to gtUint128 (for unsigned comparison)
    function toUint128(gtInt128 a) internal pure returns (gtUint128) {
        return gtUint128.wrap(gtInt128.unwrap(a));
    }

    // Helper to convert gtInt256 to gtUint256 (for unsigned comparison)
    function toUint256(gtInt256 a) internal pure returns (gtUint256) {
        return gtUint256.wrap(gtInt256.unwrap(a));
    }

    // Helper to convert gtUint256 to gtInt256
    function fromUint256(gtUint256 a) internal pure returns (gtInt256) {
        return gtInt256.wrap(gtUint256.unwrap(a));
    }

    // Helper to convert gtUint128 to gtInt128
    function fromUint128(gtUint128 a) internal pure returns (gtInt128) {
        return gtInt128.wrap(gtUint128.unwrap(a));
    }

    // Helper to reinterpret int128 as uint128 (preserve bits)
    function int128ToUint128(int128 x) internal pure returns (uint128) {
        return uint128(uint256(uint128(x)));
    }
    
    function uint128ToInt128(uint128 x) internal pure returns (int128) {
        return int128(x);
    }
}
