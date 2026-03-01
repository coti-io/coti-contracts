// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedInt8TestsContract {
    int8 public validateResult;
    int8 public addResult;
    int8 public subResult;
    int8 public mulResult;
    int8 public divResult;
    int8 public andResult;
    int8 public orResult;
    int8 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctInt8 public offBoardResult;
    ctInt8 public offBoardToUserResult;
    utInt8 public offBoardCombinedResult;
    int8 public onBoardResult1;
    int8 public onBoardResult2;

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

    function validateCiphertextTest(itInt8 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int8 a, int8 b) public {
        addResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.add(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        addResult = result;
    }

    function subTest(int8 a, int8 b) public {
        subResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.sub(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        subResult = result;
    }

    function mulTest(int8 a, int8 b) public {
        mulResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.mul(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        mulResult = result;
    }

    function divTest(int8 a, int8 b) public {
        divResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.div(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        divResult = result;
    }

    function andTest(int8 a, int8 b) public {
        andResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.and(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        andResult = result;
    }

    function orTest(int8 a, int8 b) public {
        orResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.or(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        orResult = result;
    }

    function xorTest(int8 a, int8 b) public {
        xorResult = 0;
        int8 result = MpcCore.decrypt(
            MpcCore.xor(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        xorResult = result;
    }

    function eqTest(int8 a, int8 b) public {
        eqResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.eq(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        eqResult = result;
    }

    function neTest(int8 a, int8 b) public {
        neResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.ne(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        neResult = result;
    }

    function gtTest(int8 a, int8 b) public {
        gtResult = false;
        gtInt8 gtA = MpcCore.setPublic8(a);
        gtInt8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(int8 a, int8 b) public {
        ltResult = false;
        gtInt8 gtA = MpcCore.setPublic8(a);
        gtInt8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(int8 a, int8 b) public {
        geResult = false;
        gtInt8 gtA = MpcCore.setPublic8(a);
        gtInt8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(int8 a, int8 b) public {
        leResult = false;
        gtInt8 gtA = MpcCore.setPublic8(a);
        gtInt8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(int8 a, int8 b, int8 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic8(a));
        offBoardToUserResult = MpcCore.offBoardToUser(
            MpcCore.setPublic8(b),
            msg.sender
        );
        offBoardCombinedResult = MpcCore.offBoardCombined(
            MpcCore.setPublic8(c),
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
