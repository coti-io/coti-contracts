// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract SignedIntegerTestsContract {

    struct AllGTCastingValues {
        gtInt8 a8_s;
        gtInt8 b8_s;
        // gtInt16 a16_s;
        // gtInt16 b16_s;
        // gtInt32 a32_s;
        // gtInt32 b32_s;
        // gtInt64 a64_s;
        // gtInt64 b64_s;
    }

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
    ctInt8 public offBoardResult;
    ctInt8 public offBoardToUserResult;
    utInt8 public offBoardCombinedResult;
    int8 public onBoardResult1;
    int8 public onBoardResult2;
    
    function setPublicValues(AllGTCastingValues memory castingValues, int8 a, int8 b) public {
        castingValues.a8_s = MpcCore.setPublic8(a);
        castingValues.b8_s = MpcCore.setPublic8(b);
    }

    function validateCiphertextTest(itInt8 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.add(castingValues.a8_s, castingValues.b8_s));
        addResult = result;
    }

    function subTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.sub(castingValues.a8_s, castingValues.b8_s));
        subResult = result;
    }

    function mulTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.mul(castingValues.a8_s, castingValues.b8_s));
        mulResult = result;
    }

    function divTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.div(castingValues.a8_s, castingValues.b8_s));
        divResult = result;
    }

    function andTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.and(castingValues.a8_s, castingValues.b8_s));
        andResult = result;
    }

    function orTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.or(castingValues.a8_s, castingValues.b8_s));
        orResult = result;
    }

    function xorTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        int8 result = MpcCore.decrypt(MpcCore.xor(castingValues.a8_s, castingValues.b8_s));
        xorResult = result;
    }

    function eqTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        bool result = MpcCore.decrypt(MpcCore.eq(castingValues.a8_s, castingValues.b8_s));
        eqResult = result;
    }

    function neTest(int8 a, int8 b) public {
        AllGTCastingValues memory castingValues;

        setPublicValues(castingValues, a, b);

        bool result = MpcCore.decrypt(MpcCore.ne(castingValues.a8_s, castingValues.b8_s));
        neResult = result;
    }

    function offBoardTest(int8 a, int8 b, int8 c) public {
        offBoardResult = MpcCore.offBoard(MpcCore.setPublic8(a));
        offBoardToUserResult = MpcCore.offBoardToUser(MpcCore.setPublic8(b), msg.sender);
        offBoardCombinedResult = MpcCore.offBoardCombined(MpcCore.setPublic8(c), msg.sender);
    }

    function onBoardTest() public {
        onBoardResult1 = MpcCore.decrypt(MpcCore.onBoard(offBoardResult));
        onBoardResult2 = MpcCore.decrypt(MpcCore.onBoard(offBoardCombinedResult.ciphertext));
    }

}