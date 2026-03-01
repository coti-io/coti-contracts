// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract UnsignedInt8TestsContract {
    uint8 public validateResult;
    uint8 public addResult;
    uint8 public subResult;
    uint8 public mulResult;
    uint8 public divResult;
    uint8 public andResult;
    uint8 public orResult;
    uint8 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    ctUint8 public offBoardResult;
    ctUint8 public offBoardToUserResult;
    utUint8 public offBoardCombinedResult;
    uint8 public onBoardResult1;
    uint8 public onBoardResult2;

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

    function validateCiphertextTest(itUint8 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(uint8 a, uint8 b) public {
        addResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.add(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        addResult = result;
    }

    function subTest(uint8 a, uint8 b) public {
        subResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.sub(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        subResult = result;
    }

    function mulTest(uint8 a, uint8 b) public {
        mulResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.mul(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        mulResult = result;
    }

    function divTest(uint8 a, uint8 b) public {
        divResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.div(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        divResult = result;
    }

    function andTest(uint8 a, uint8 b) public {
        andResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.and(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        andResult = result;
    }

    function orTest(uint8 a, uint8 b) public {
        orResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.or(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        orResult = result;
    }

    function xorTest(uint8 a, uint8 b) public {
        xorResult = 0;
        uint8 result = MpcCore.decrypt(
            MpcCore.xor(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        xorResult = result;
    }

    function eqTest(uint8 a, uint8 b) public {
        eqResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.eq(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        eqResult = result;
    }

    function neTest(uint8 a, uint8 b) public {
        neResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.ne(MpcCore.setPublic8(a), MpcCore.setPublic8(b))
        );
        neResult = result;
    }

    function gtTest(uint8 a, uint8 b) public {
        gtResult = false;
        gtUint8 gtA = MpcCore.setPublic8(a);
        gtUint8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(uint8 a, uint8 b) public {
        ltResult = false;
        gtUint8 gtA = MpcCore.setPublic8(a);
        gtUint8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(uint8 a, uint8 b) public {
        geResult = false;
        gtUint8 gtA = MpcCore.setPublic8(a);
        gtUint8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(uint8 a, uint8 b) public {
        leResult = false;
        gtUint8 gtA = MpcCore.setPublic8(a);
        gtUint8 gtB = MpcCore.setPublic8(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(uint8 a, uint8 b, uint8 c) public {
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
