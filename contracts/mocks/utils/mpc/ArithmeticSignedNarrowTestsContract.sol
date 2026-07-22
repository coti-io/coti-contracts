// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/// @dev Narrow signed widths (8/16/32/64) — split from ArithmeticSigned256TestsContract for EIP-170.
contract ArithmeticSignedNarrowTestsContract {
    function basicSigned8Test() public {
        gtInt8 a = MpcCore.setPublic8(int8(-12));
        gtInt8 b = MpcCore.setPublic8(int8(3));
        gtInt8 sameA = MpcCore.setPublic8(int8(-12));

        require(MpcCore.decrypt(MpcCore.add(a, b)) == -9, "int8 add");
        require(MpcCore.decrypt(MpcCore.sub(a, b)) == -15, "int8 sub");
        require(MpcCore.decrypt(MpcCore.mul(a, b)) == -36, "int8 mul");
        require(MpcCore.decrypt(MpcCore.div(a, b)) == -4, "int8 div");
        require(MpcCore.decrypt(MpcCore.checkedAdd(a, b)) == -9, "int8 checked add");
        require(MpcCore.decrypt(MpcCore.checkedSub(a, b)) == -15, "int8 checked sub");
        require(MpcCore.decrypt(MpcCore.checkedMul(a, b)) == -36, "int8 checked mul");
        require(MpcCore.decrypt(MpcCore.eq(a, sameA)), "int8 eq");
        require(MpcCore.decrypt(MpcCore.ne(a, b)), "int8 ne");
        require(MpcCore.decrypt(MpcCore.lt(a, b)), "int8 lt");
        require(MpcCore.decrypt(MpcCore.le(a, sameA)), "int8 le");
        require(MpcCore.decrypt(MpcCore.gt(b, a)), "int8 gt");
        require(MpcCore.decrypt(MpcCore.ge(sameA, a)), "int8 ge");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(true), a, b)) == 3, "int8 mux true");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(false), a, b)) == -12, "int8 mux false");
        require(MpcCore.decrypt(MpcCore.shl(MpcCore.setPublic8(int8(-8)), 1)) == -16, "int8 shl");
        require(MpcCore.decrypt(MpcCore.shr(MpcCore.setPublic8(int8(-8)), 1)) == -4, "int8 shr");
    }

    function basicSigned16Test() public {
        gtInt16 a = MpcCore.setPublic16(int16(-12));
        gtInt16 b = MpcCore.setPublic16(int16(3));
        gtInt16 sameA = MpcCore.setPublic16(int16(-12));

        require(MpcCore.decrypt(MpcCore.add(a, b)) == -9, "int16 add");
        require(MpcCore.decrypt(MpcCore.sub(a, b)) == -15, "int16 sub");
        require(MpcCore.decrypt(MpcCore.mul(a, b)) == -36, "int16 mul");
        require(MpcCore.decrypt(MpcCore.div(a, b)) == -4, "int16 div");
        require(MpcCore.decrypt(MpcCore.checkedAdd(a, b)) == -9, "int16 checked add");
        require(MpcCore.decrypt(MpcCore.checkedSub(a, b)) == -15, "int16 checked sub");
        require(MpcCore.decrypt(MpcCore.checkedMul(a, b)) == -36, "int16 checked mul");
        require(MpcCore.decrypt(MpcCore.eq(a, sameA)), "int16 eq");
        require(MpcCore.decrypt(MpcCore.ne(a, b)), "int16 ne");
        require(MpcCore.decrypt(MpcCore.lt(a, b)), "int16 lt");
        require(MpcCore.decrypt(MpcCore.le(a, sameA)), "int16 le");
        require(MpcCore.decrypt(MpcCore.gt(b, a)), "int16 gt");
        require(MpcCore.decrypt(MpcCore.ge(sameA, a)), "int16 ge");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(true), a, b)) == 3, "int16 mux true");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(false), a, b)) == -12, "int16 mux false");
        require(MpcCore.decrypt(MpcCore.shl(MpcCore.setPublic16(int16(-8)), 1)) == -16, "int16 shl");
        require(MpcCore.decrypt(MpcCore.shr(MpcCore.setPublic16(int16(-8)), 1)) == -4, "int16 shr");
    }

    function basicSigned32Test() public {
        gtInt32 a = MpcCore.setPublic32(int32(-12));
        gtInt32 b = MpcCore.setPublic32(int32(3));
        gtInt32 sameA = MpcCore.setPublic32(int32(-12));

        require(MpcCore.decrypt(MpcCore.add(a, b)) == -9, "int32 add");
        require(MpcCore.decrypt(MpcCore.sub(a, b)) == -15, "int32 sub");
        require(MpcCore.decrypt(MpcCore.mul(a, b)) == -36, "int32 mul");
        require(MpcCore.decrypt(MpcCore.div(a, b)) == -4, "int32 div");
        require(MpcCore.decrypt(MpcCore.checkedAdd(a, b)) == -9, "int32 checked add");
        require(MpcCore.decrypt(MpcCore.checkedSub(a, b)) == -15, "int32 checked sub");
        require(MpcCore.decrypt(MpcCore.checkedMul(a, b)) == -36, "int32 checked mul");
        require(MpcCore.decrypt(MpcCore.eq(a, sameA)), "int32 eq");
        require(MpcCore.decrypt(MpcCore.ne(a, b)), "int32 ne");
        require(MpcCore.decrypt(MpcCore.lt(a, b)), "int32 lt");
        require(MpcCore.decrypt(MpcCore.le(a, sameA)), "int32 le");
        require(MpcCore.decrypt(MpcCore.gt(b, a)), "int32 gt");
        require(MpcCore.decrypt(MpcCore.ge(sameA, a)), "int32 ge");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(true), a, b)) == 3, "int32 mux true");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(false), a, b)) == -12, "int32 mux false");
        require(MpcCore.decrypt(MpcCore.shl(MpcCore.setPublic32(int32(-8)), 1)) == -16, "int32 shl");
        require(MpcCore.decrypt(MpcCore.shr(MpcCore.setPublic32(int32(-8)), 1)) == -4, "int32 shr");
    }

    function basicSigned64Test() public {
        gtInt64 a = MpcCore.setPublic64(int64(-12));
        gtInt64 b = MpcCore.setPublic64(int64(3));
        gtInt64 sameA = MpcCore.setPublic64(int64(-12));

        require(MpcCore.decrypt(MpcCore.add(a, b)) == -9, "int64 add");
        require(MpcCore.decrypt(MpcCore.sub(a, b)) == -15, "int64 sub");
        require(MpcCore.decrypt(MpcCore.mul(a, b)) == -36, "int64 mul");
        require(MpcCore.decrypt(MpcCore.div(a, b)) == -4, "int64 div");
        require(MpcCore.decrypt(MpcCore.checkedAdd(a, b)) == -9, "int64 checked add");
        require(MpcCore.decrypt(MpcCore.checkedSub(a, b)) == -15, "int64 checked sub");
        require(MpcCore.decrypt(MpcCore.checkedMul(a, b)) == -36, "int64 checked mul");
        require(MpcCore.decrypt(MpcCore.eq(a, sameA)), "int64 eq");
        require(MpcCore.decrypt(MpcCore.ne(a, b)), "int64 ne");
        require(MpcCore.decrypt(MpcCore.lt(a, b)), "int64 lt");
        require(MpcCore.decrypt(MpcCore.le(a, sameA)), "int64 le");
        require(MpcCore.decrypt(MpcCore.gt(b, a)), "int64 gt");
        require(MpcCore.decrypt(MpcCore.ge(sameA, a)), "int64 ge");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(true), a, b)) == 3, "int64 mux true");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(false), a, b)) == -12, "int64 mux false");
        require(MpcCore.decrypt(MpcCore.shl(MpcCore.setPublic64(int64(-8)), 1)) == -16, "int64 shl");
        require(MpcCore.decrypt(MpcCore.shr(MpcCore.setPublic64(int64(-8)), 1)) == -4, "int64 shr");
    }

    function minDivMinusOne8Test() public {
        require(
            MpcCore.decrypt(MpcCore.div(MpcCore.setPublic8(type(int8).min), MpcCore.setPublic8(int8(-1))))
                == type(int8).min,
            "int8 min div -1"
        );
    }

    function checkedAdd8OverflowTest() public {
        MpcCore.checkedAdd(MpcCore.setPublic8(type(int8).max), MpcCore.setPublic8(int8(1)));
    }

    function checkedSub8UnderflowTest() public {
        MpcCore.checkedSub(MpcCore.setPublic8(type(int8).min), MpcCore.setPublic8(int8(1)));
    }

    function checkedMul8OverflowTest() public {
        MpcCore.checkedMul(MpcCore.setPublic8(int8(64)), MpcCore.setPublic8(int8(2)));
    }
}
