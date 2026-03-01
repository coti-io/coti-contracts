// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedInt256TestsContract {
    int256 public validateResult;
    int256 public addResult;
    int256 public subResult;
    int256 public mulResult;
    int256 public divResult;
    int256 public andResult;
    int256 public orResult;
    int256 public xorResult;
    int256 public muxResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt256 public offBoardResult;
    ctInt256 public offBoardToUserResult;
    utInt256 public offBoardCombinedResult;
    int256 public onBoardResult1;
    int256 public onBoardResult2;
    int256 public setPublicResult;

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

    function validateCiphertextTest(itInt256 calldata value) public {
        validateResult = 0;
        itInt256 memory valueMem = value;
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(valueMem));
    }

    function addTest(int256 a, int256 b) public {
        addResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.add(gtA, gtB));
        addResult = result;
    }

    function subTest(int256 a, int256 b) public {
        subResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.sub(gtA, gtB));
        subResult = result;
    }

    function mulTest(int256 a, int256 b) public {
        mulResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.mul(gtA, gtB));
        mulResult = result;
    }

    function divTest(int256 a, int256 b) public {
        divResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.div(gtA, gtB));
        divResult = result;
    }

    function andTest(int256 a, int256 b) public {
        andResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.and(gtA, gtB));
        andResult = result;
    }

    function orTest(int256 a, int256 b) public {
        orResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.or(gtA, gtB));
        orResult = result;
    }

    function xorTest(int256 a, int256 b) public {
        xorResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        int256 result = MpcCore.decrypt(MpcCore.xor(gtA, gtB));
        xorResult = result;
    }

    function muxTest(bool bit, int256 a, int256 b) public {
        muxResult = 0;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        gtBool gtBit = MpcCore.setPublic(bit);
        int256 result = MpcCore.decrypt(MpcCore.mux(gtBit, gtA, gtB));
        muxResult = result;
    }

    function eqTest(int256 a, int256 b) public {
        eqResult = false;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        bool result = MpcCore.decrypt(MpcCore.eq(gtA, gtB));
        eqResult = result;
    }

    function neTest(int256 a, int256 b) public {
        neResult = false;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        bool result = MpcCore.decrypt(MpcCore.ne(gtA, gtB));
        neResult = result;
    }

    function gtTest(int256 a, int256 b) public {
        gtResult = false;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        bool result = MpcCore.decrypt(MpcCore.gt(gtA, gtB));
        gtResult = result;
    }

    function ltTest(int256 a, int256 b) public {
        ltResult = false;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        bool result = MpcCore.decrypt(MpcCore.lt(gtA, gtB));
        ltResult = result;
    }

    function geTest(int256 a, int256 b) public {
        geResult = false;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        bool result = MpcCore.decrypt(MpcCore.ge(gtA, gtB));
        geResult = result;
    }

    function leTest(int256 a, int256 b) public {
        leResult = false;
        gtInt256 gtA = MpcCore.setPublic256(a);
        gtInt256 gtB = MpcCore.setPublic256(b);
        bool result = MpcCore.decrypt(MpcCore.le(gtA, gtB));
        leResult = result;
    }

    function offBoardTest(int256 a, int256 b, int256 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic256(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic256(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic256(c),
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

    function setPublicTest(int256 value) public {
        setPublicResult = 0;
        gtInt256 gt = MpcCore.setPublic256(value);
        setPublicResult = MpcCore.decrypt(gt);
    }
} 