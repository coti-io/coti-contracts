// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedInt128TestsContract {
    int128 public validateResult;
    int128 public addResult;
    int128 public subResult;
    int128 public mulResult;
    int128 public divResult;
    int128 public andResult;
    int128 public orResult;
    int128 public xorResult;
    int128 public muxResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt128 public offBoardResult;
    ctInt128 public offBoardToUserResult;
    utInt128 public offBoardCombinedResult;
    int128 public onBoardResult1;
    int128 public onBoardResult2;
    int128 public setPublicResult;

    // Reset function to clear all state and potentially help with state pollution
    function resetState() public {
        validateResult = 0;
        addResult = 0;
        subResult = 0;
        mulResult = 0;
        divResult = 0;
        andResult = 0;
        orResult = 0;
        xorResult = 0;
        muxResult = 0;
        eqResult = false;
        neResult = false;
        gtResult = false;
        ltResult = false;
        geResult = false;
        leResult = false;
        onBoardResult1 = 0;
        onBoardResult2 = 0;
    }

    function validateCiphertextTest(itInt128 calldata value) public {
        validateResult = 0;
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int128 a, int128 b) public {
        addResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.add(gtA, gtB));
        addResult = result;
    }

    function subTest(int128 a, int128 b) public {
        subResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.sub(gtA, gtB));
        subResult = result;
    }

    function mulTest(int128 a, int128 b) public {
        mulResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.mul(gtA, gtB));
        mulResult = result;
    }

    function divTest(int128 a, int128 b) public {
        divResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.div(gtA, gtB));
        divResult = result;
    }

    function andTest(int128 a, int128 b) public {
        andResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.and(gtA, gtB));
        andResult = result;
    }

    function orTest(int128 a, int128 b) public {
        orResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.or(gtA, gtB));
        orResult = result;
    }

    function xorTest(int128 a, int128 b) public {
        xorResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        int128 result = MpcCore.decrypt(MpcCore.xor(gtA, gtB));
        xorResult = result;
    }

    function muxTest(bool bit, int128 a, int128 b) public {
        muxResult = 0;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);
        gtBool gtBit = MpcCore.setPublic(bit);
        int128 result = MpcCore.decrypt(MpcCore.mux(gtBit, gtA, gtB));
        muxResult = result;
    }

    function eqTest(int128 a, int128 b) public {
        eqResult = false;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        bool result = MpcCore.decrypt(MpcCore.eq(gtA, gtB));
        eqResult = result;
    }

    function neTest(int128 a, int128 b) public {
        neResult = false;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        bool result = MpcCore.decrypt(MpcCore.ne(gtA, gtB));
        neResult = result;
    }

    function gtTest(int128 a, int128 b) public {
        gtResult = false;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(int128 a, int128 b) public {
        ltResult = false;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(int128 a, int128 b) public {
        geResult = false;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(int128 a, int128 b) public {
        leResult = false;
        gtInt128 gtA = MpcCore.setPublic128(a);
        gtInt128 gtB = MpcCore.setPublic128(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(int128 a, int128 b, int128 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic128(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic128(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic128(c),
            msg.sender
        );
    }

    function onBoardTest() public {
        onBoardResult1 = 0;
        onBoardResult2 = 0;
        onBoardResult1 = MpcCore.decrypt(MpcCore.onBoard(offBoardResult));
        onBoardResult2 = MpcCore.decrypt(
            MpcCore.onBoard(offBoardCombinedResult.ciphertext)
        );
    }

    function setPublicTest(int128 value) public {
        setPublicResult = 0;
        gtInt128 gt = MpcCore.setPublic128(value);
        setPublicResult = MpcCore.decrypt(gt);
    }
}
