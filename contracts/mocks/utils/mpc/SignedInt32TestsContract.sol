// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedInt32TestsContract {
    int32 public validateResult;
    int32 public addResult;
    int32 public subResult;
    int32 public mulResult;
    int32 public divResult;
    int32 public andResult;
    int32 public orResult;
    int32 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt32 public offBoardResult;
    ctInt32 public offBoardToUserResult;
    utInt32 public offBoardCombinedResult;
    int32 public onBoardResult1;
    int32 public onBoardResult2;

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

    function validateCiphertextTest(itInt32 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int32 a, int32 b) public {
        addResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.add(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        addResult = result;
    }

    function subTest(int32 a, int32 b) public {
        subResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.sub(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        subResult = result;
    }

    function mulTest(int32 a, int32 b) public {
        mulResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.mul(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        mulResult = result;
    }

    function divTest(int32 a, int32 b) public {
        divResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.div(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        divResult = result;
    }

    function andTest(int32 a, int32 b) public {
        andResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.and(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        andResult = result;
    }

    function orTest(int32 a, int32 b) public {
        orResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.or(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        orResult = result;
    }

    function xorTest(int32 a, int32 b) public {
        xorResult = 0;
        int32 result = MpcCore.decrypt(
            MpcCore.xor(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        xorResult = result;
    }

    function eqTest(int32 a, int32 b) public {
        eqResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.eq(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        eqResult = result;
    }

    function neTest(int32 a, int32 b) public {
        neResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.ne(MpcCore.setPublic32(a), MpcCore.setPublic32(b))
        );
        neResult = result;
    }

    function gtTest(int32 a, int32 b) public {
        gtResult = false;
        gtInt32 gtA = MpcCore.setPublic32(a);
        gtInt32 gtB = MpcCore.setPublic32(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(int32 a, int32 b) public {
        ltResult = false;
        gtInt32 gtA = MpcCore.setPublic32(a);
        gtInt32 gtB = MpcCore.setPublic32(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(int32 a, int32 b) public {
        geResult = false;
        gtInt32 gtA = MpcCore.setPublic32(a);
        gtInt32 gtB = MpcCore.setPublic32(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(int32 a, int32 b) public {
        leResult = false;
        gtInt32 gtA = MpcCore.setPublic32(a);
        gtInt32 gtB = MpcCore.setPublic32(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(int32 a, int32 b, int32 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic32(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic32(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic32(c),
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
