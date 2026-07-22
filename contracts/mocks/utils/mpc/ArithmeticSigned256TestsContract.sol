// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

/// @dev Signed int256 + checked storage helpers — narrow/128 widths live in sibling mocks (EIP-170).
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

    function minDivMinusOne256Test() public {
        require(
            MpcCore.decrypt(MpcCore.div(MpcCore.setPublic256(type(int256).min), MpcCore.setPublic256(int256(-1))))
                == type(int256).min,
            "int256 min div -1"
        );
    }

    function plainMul256WrapTest() public {
        require(
            MpcCore.decrypt(MpcCore.mul(MpcCore.setPublic256(int256(1) << 128), MpcCore.setPublic256(int256(1) << 128)))
                == 0,
            "int256 mul wrap"
        );
    }
}
