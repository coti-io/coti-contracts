// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedInt16TestsContract {
    int16 public validateResult;
    int16 public addResult;
    int16 public subResult;
    int16 public mulResult;
    int16 public divResult;
    int16 public andResult;
    int16 public orResult;
    int16 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt16 public offBoardResult;
    ctInt16 public offBoardToUserResult;
    utInt16 public offBoardCombinedResult;
    int16 public onBoardResult1;
    int16 public onBoardResult2;

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

    function validateCiphertextTest(itInt16 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int16 a, int16 b) public {
        addResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.add(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        addResult = result;
    }

    function subTest(int16 a, int16 b) public {
        subResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.sub(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        subResult = result;
    }

    function mulTest(int16 a, int16 b) public {
        mulResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.mul(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        mulResult = result;
    }

    function divTest(int16 a, int16 b) public {
        divResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.div(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        divResult = result;
    }

    function andTest(int16 a, int16 b) public {
        andResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.and(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        andResult = result;
    }

    function orTest(int16 a, int16 b) public {
        orResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.or(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        orResult = result;
    }

    function xorTest(int16 a, int16 b) public {
        xorResult = 0;
        int16 result = MpcCore.decrypt(
            MpcCore.xor(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        xorResult = result;
    }

    function eqTest(int16 a, int16 b) public {
        eqResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.eq(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        eqResult = result;
    }

    function neTest(int16 a, int16 b) public {
        neResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.ne(MpcCore.setPublic16(a), MpcCore.setPublic16(b))
        );
        neResult = result;
    }

    function gtTest(int16 a, int16 b) public {
        gtResult = false;
        gtInt16 gtA = MpcCore.setPublic16(a);
        gtInt16 gtB = MpcCore.setPublic16(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(int16 a, int16 b) public {
        ltResult = false;
        gtInt16 gtA = MpcCore.setPublic16(a);
        gtInt16 gtB = MpcCore.setPublic16(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(int16 a, int16 b) public {
        geResult = false;
        gtInt16 gtA = MpcCore.setPublic16(a);
        gtInt16 gtB = MpcCore.setPublic16(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(int16 a, int16 b) public {
        leResult = false;
        gtInt16 gtA = MpcCore.setPublic16(a);
        gtInt16 gtB = MpcCore.setPublic16(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(int16 a, int16 b, int16 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic16(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic16(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic16(c),
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
