// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedInt64TestsContract {
    int64 public validateResult;
    int64 public addResult;
    int64 public subResult;
    int64 public mulResult;
    int64 public divResult;
    int64 public andResult;
    int64 public orResult;
    int64 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt64 public offBoardResult;
    ctInt64 public offBoardToUserResult;
    utInt64 public offBoardCombinedResult;
    int64 public onBoardResult1;
    int64 public onBoardResult2;

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
        eqResult = false;
        neResult = false;
        gtResult = false;
        ltResult = false;
        geResult = false;
        leResult = false;
        onBoardResult1 = 0;
        onBoardResult2 = 0;
        // Note: offBoardResult, offBoardToUserResult, offBoardCombinedResult 
        // are complex types and harder to reset cleanly
    }

    function validateCiphertextTest(itInt64 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int64 a, int64 b) public {
        addResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.add(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        addResult = result;
    }

    function subTest(int64 a, int64 b) public {
        subResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.sub(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        subResult = result;
    }

    function mulTest(int64 a, int64 b) public {
        mulResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.mul(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        mulResult = result;
    }

    function divTest(int64 a, int64 b) public {
        divResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.div(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        divResult = result;
    }

    function andTest(int64 a, int64 b) public {
        andResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.and(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        andResult = result;
    }

    function orTest(int64 a, int64 b) public {
        orResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.or(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        orResult = result;
    }

    function xorTest(int64 a, int64 b) public {
        xorResult = 0;
        int64 result = MpcCore.decrypt(
            MpcCore.xor(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        xorResult = result;
    }

    function eqTest(int64 a, int64 b) public {
        eqResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.eq(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        eqResult = result;
    }

    function neTest(int64 a, int64 b) public {
        neResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.ne(MpcCore.setPublic64(a), MpcCore.setPublic64(b))
        );
        neResult = result;
    }

    function gtTest(int64 a, int64 b) public {
        gtResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(int64 a, int64 b) public {
        ltResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(int64 a, int64 b) public {
        geResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(int64 a, int64 b) public {
        leResult = false;
        gtInt64 gtA = MpcCore.setPublic64(a);
        gtInt64 gtB = MpcCore.setPublic64(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(int64 a, int64 b, int64 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic64(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic64(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic64(c),
            msg.sender
        );
    }

    function onBoardTest() public {
        onBoardResult1 = MpcCore.decrypt(MpcCore.onBoard(offBoardResult));
        onBoardResult2 = MpcCore.decrypt(
            MpcCore.onBoard(offBoardCombinedResult.ciphertext)
        );
    }
}
