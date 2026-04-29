// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract ArithmeticSigned256TestsContract {
    int256 addResult;
    int256 subResult;
    int256 mulResult;

    function getAddResult() public view returns (int256) {
        return addResult;
    }

    function getSubResult() public view returns (int256) {
        return subResult;
    }

    function getMulResult() public view returns (int256) {
        return mulResult;
    }

    function checkedAddTest(int256 a, int256 b) public returns (int256) {
        gtInt256 a256 = MpcCore.setPublic256(a);
        gtInt256 b256 = MpcCore.setPublic256(b);

        int256 result = MpcCore.decrypt(MpcCore.checkedAdd(a256, b256));
        addResult = result;

        return result;
    }

    function checkedSubTest(int256 a, int256 b) public returns (int256) {
        gtInt256 a256 = MpcCore.setPublic256(a);
        gtInt256 b256 = MpcCore.setPublic256(b);

        int256 result = MpcCore.decrypt(MpcCore.checkedSub(a256, b256));
        subResult = result;

        return result;
    }

    function checkedMulTest(int256 a, int256 b) public returns (int256) {
        gtInt256 a256 = MpcCore.setPublic256(a);
        gtInt256 b256 = MpcCore.setPublic256(b);

        int256 result = MpcCore.decrypt(MpcCore.checkedMul(a256, b256));
        mulResult = result;

        return result;
    }

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

    function basicSigned128Test() public {
        gtInt128 a = MpcCore.setPublic128(int128(-12));
        gtInt128 b = MpcCore.setPublic128(int128(3));
        gtInt128 sameA = MpcCore.setPublic128(int128(-12));

        require(MpcCore.decrypt(MpcCore.add(a, b)) == -9, "int128 add");
        require(MpcCore.decrypt(MpcCore.sub(a, b)) == -15, "int128 sub");
        require(MpcCore.decrypt(MpcCore.mul(a, b)) == -36, "int128 mul");
        require(MpcCore.decrypt(MpcCore.div(a, b)) == -4, "int128 div");
        require(MpcCore.decrypt(MpcCore.checkedAdd(a, b)) == -9, "int128 checked add");
        require(MpcCore.decrypt(MpcCore.checkedSub(a, b)) == -15, "int128 checked sub");
        require(MpcCore.decrypt(MpcCore.checkedMul(a, b)) == -36, "int128 checked mul");
        require(MpcCore.decrypt(MpcCore.eq(a, sameA)), "int128 eq");
        require(MpcCore.decrypt(MpcCore.ne(a, b)), "int128 ne");
        require(MpcCore.decrypt(MpcCore.lt(a, b)), "int128 lt");
        require(MpcCore.decrypt(MpcCore.le(a, sameA)), "int128 le");
        require(MpcCore.decrypt(MpcCore.gt(b, a)), "int128 gt");
        require(MpcCore.decrypt(MpcCore.ge(sameA, a)), "int128 ge");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(true), a, b)) == 3, "int128 mux true");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(false), a, b)) == -12, "int128 mux false");
        require(MpcCore.decrypt(MpcCore.toSigned(MpcCore.fromSigned(a))) == -12, "int128 conversion");
        require(MpcCore.decrypt(MpcCore.negate(a)) == 12, "int128 negate");
        require(MpcCore.decrypt(MpcCore.shl(MpcCore.setPublic128(int128(-8)), 1)) == -16, "int128 shl");
        require(MpcCore.decrypt(MpcCore.shr(MpcCore.setPublic128(int128(-8)), 1)) == -4, "int128 shr");
        require(MpcCore.int128ToUint128(-1) == type(uint128).max, "int128 to uint128");
        require(MpcCore.uint128ToInt128(type(uint128).max) == -1, "uint128 to int128");
    }

    function basicSigned256ArithmeticTest() public {
        gtInt256 a = MpcCore.setPublic256(int256(-12));
        gtInt256 b = MpcCore.setPublic256(int256(3));

        require(MpcCore.decrypt(MpcCore.add(a, b)) == -9, "int256 add");
        require(MpcCore.decrypt(MpcCore.sub(a, b)) == -15, "int256 sub");
        require(MpcCore.decrypt(MpcCore.mul(a, b)) == -36, "int256 mul");
        require(MpcCore.decrypt(MpcCore.div(a, b)) == -4, "int256 div");
        require(MpcCore.decrypt(MpcCore.checkedAdd(a, b)) == -9, "int256 checked add");
        require(MpcCore.decrypt(MpcCore.checkedSub(a, b)) == -15, "int256 checked sub");
        require(MpcCore.decrypt(MpcCore.checkedMul(a, b)) == -36, "int256 checked mul");
    }

    function basicSigned256ComparisonTest() public {
        gtInt256 a = MpcCore.setPublic256(int256(-12));
        gtInt256 b = MpcCore.setPublic256(int256(3));
        gtInt256 sameA = MpcCore.setPublic256(int256(-12));

        require(MpcCore.decrypt(MpcCore.eq(a, sameA)), "int256 eq");
        require(MpcCore.decrypt(MpcCore.ne(a, b)), "int256 ne");
        require(MpcCore.decrypt(MpcCore.lt(a, b)), "int256 lt");
        require(MpcCore.decrypt(MpcCore.le(a, sameA)), "int256 le");
        require(MpcCore.decrypt(MpcCore.gt(b, a)), "int256 gt");
        require(MpcCore.decrypt(MpcCore.ge(sameA, a)), "int256 ge");
    }

    function basicSigned256MuxAndHelpersTest() public {
        gtInt256 a = MpcCore.setPublic256(int256(-12));
        gtInt256 b = MpcCore.setPublic256(int256(3));

        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(true), a, b)) == 3, "int256 mux true");
        require(MpcCore.decrypt(MpcCore.mux(MpcCore.setPublic(false), a, b)) == -12, "int256 mux false");
        require(MpcCore.decrypt(MpcCore.toSigned(MpcCore.fromSigned(a))) == -12, "int256 conversion");
        require(MpcCore.decrypt(MpcCore.negate(a)) == 12, "int256 negate");
        require(MpcCore.int64ToUint64(-1) == type(uint64).max, "int64 to uint64");
        require(MpcCore.uint64ToInt64(type(uint64).max) == -1, "uint64 to int64");
    }

    function minDivMinusOne8Test() public {
        require(MpcCore.decrypt(MpcCore.div(MpcCore.setPublic8(type(int8).min), MpcCore.setPublic8(int8(-1)))) == type(int8).min, "int8 min div -1");
    }

    function minDivMinusOne128Test() public {
        require(MpcCore.decrypt(MpcCore.div(MpcCore.setPublic128(type(int128).min), MpcCore.setPublic128(int128(-1)))) == type(int128).min, "int128 min div -1");
    }

    function minDivMinusOne256Test() public {
        require(MpcCore.decrypt(MpcCore.div(MpcCore.setPublic256(type(int256).min), MpcCore.setPublic256(int256(-1)))) == type(int256).min, "int256 min div -1");
    }

    function plainMul128WrapTest() public {
        require(MpcCore.decrypt(MpcCore.mul(MpcCore.setPublic128(int128(1) << 64), MpcCore.setPublic128(int128(1) << 64))) == 0, "int128 mul wrap");
    }

    function plainMul256WrapTest() public {
        require(MpcCore.decrypt(MpcCore.mul(MpcCore.setPublic256(int256(1) << 128), MpcCore.setPublic256(int256(1) << 128))) == 0, "int256 mul wrap");
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

    function checkedAdd128OverflowTest() public {
        MpcCore.checkedAdd(MpcCore.setPublic128(type(int128).max), MpcCore.setPublic128(int128(1)));
    }

    function checkedSub128UnderflowTest() public {
        MpcCore.checkedSub(MpcCore.setPublic128(type(int128).min), MpcCore.setPublic128(int128(1)));
    }

    function checkedMul128OverflowTest() public {
        MpcCore.checkedMul(MpcCore.setPublic128(int128(1) << 64), MpcCore.setPublic128(int128(1) << 64));
    }
}
