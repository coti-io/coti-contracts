// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/// @dev Signed int128 coverage — split from ArithmeticSigned256TestsContract for EIP-170.
contract ArithmeticSigned128TestsContract {
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

    function minDivMinusOne128Test() public {
        require(
            MpcCore.decrypt(MpcCore.div(MpcCore.setPublic128(type(int128).min), MpcCore.setPublic128(int128(-1))))
                == type(int128).min,
            "int128 min div -1"
        );
    }

    function plainMul128WrapTest() public {
        require(
            MpcCore.decrypt(MpcCore.mul(MpcCore.setPublic128(int128(1) << 64), MpcCore.setPublic128(int128(1) << 64)))
                == 0,
            "int128 mul wrap"
        );
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
