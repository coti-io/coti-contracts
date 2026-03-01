// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract UnsignedInt256TestsContract {
    uint256 public validateResult;
    uint256 public addResult;
    uint256 public subResult;
    uint256 public mulResult;
    uint256 public divResult;
    uint256 public andResult;
    uint256 public orResult;
    uint256 public xorResult;
    bool public eqResult;
    bool public neResult;
    bool public gtResult;
    bool public ltResult;
    bool public geResult;
    bool public leResult;
    // Note: ctUint256 is a struct and cannot be stored directly in storage
    // For offBoard functionality, we'll use arrays like the existing 256-bit tests
    ctUint256[] public offBoardResults;
    ctUint256[] public offBoardToUserResults;
    utUint256[] public offBoardCombinedResults;
    uint256[] public onBoardResults;

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
        // Clear arrays
        delete offBoardResults;
        delete offBoardToUserResults;
        delete offBoardCombinedResults;
        delete onBoardResults;
    }

    function validateCiphertextTest(itUint256 calldata value) public {
        validateResult = MpcCore.decrypt(MpcCore.validateCiphertext(value));
    }

    function addTest(uint256 a, uint256 b) public {
        addResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.add(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        addResult = result;
    }

    function subTest(uint256 a, uint256 b) public {
        subResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.sub(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        subResult = result;
    }

    function mulTest(uint256 a, uint256 b) public {
        mulResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.mul(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        mulResult = result;
    }

    function divTest(uint256 a, uint256 b) public {
        divResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.div(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        divResult = result;
    }

    function andTest(uint256 a, uint256 b) public {
        andResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.and(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        andResult = result;
    }

    function orTest(uint256 a, uint256 b) public {
        orResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.or(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        orResult = result;
    }

    function xorTest(uint256 a, uint256 b) public {
        xorResult = 0;
        uint256 result = MpcCore.decrypt(
            MpcCore.xor(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        xorResult = result;
    }

    function eqTest(uint256 a, uint256 b) public {
        eqResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.eq(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        eqResult = result;
    }

    function neTest(uint256 a, uint256 b) public {
        neResult = false;
        bool result = MpcCore.decrypt(
            MpcCore.ne(MpcCore.setPublic256(a), MpcCore.setPublic256(b))
        );
        neResult = result;
    }

    function gtTest(uint256 a, uint256 b) public {
        gtResult = false;
        gtUint256 gtA = MpcCore.setPublic256(a);
        gtUint256 gtB = MpcCore.setPublic256(b);

        gtBool result = MpcCore.gt(gtA, gtB);
        gtResult = MpcCore.decrypt(result);
    }

    function ltTest(uint256 a, uint256 b) public {
        ltResult = false;
        gtUint256 gtA = MpcCore.setPublic256(a);
        gtUint256 gtB = MpcCore.setPublic256(b);

        gtBool result = MpcCore.lt(gtA, gtB);
        ltResult = MpcCore.decrypt(result);
    }

    function geTest(uint256 a, uint256 b) public {
        geResult = false;
        gtUint256 gtA = MpcCore.setPublic256(a);
        gtUint256 gtB = MpcCore.setPublic256(b);

        gtBool result = MpcCore.ge(gtA, gtB);
        geResult = MpcCore.decrypt(result);
    }

    function leTest(uint256 a, uint256 b) public {
        leResult = false;
        gtUint256 gtA = MpcCore.setPublic256(a);
        gtUint256 gtB = MpcCore.setPublic256(b);

        gtBool result = MpcCore.le(gtA, gtB);
        leResult = MpcCore.decrypt(result);
    }

    function offBoardTest(uint256 a, uint256 b, uint256 c) public {
        offBoardResults.push(MpcCore.offBoard(MpcCore.setPublic256(a)));
        offBoardToUserResults.push(MpcCore.offBoardToUser(
            MpcCore.setPublic256(b),
            msg.sender
        ));
        offBoardCombinedResults.push(MpcCore.offBoardCombined(
            MpcCore.setPublic256(c),
            msg.sender
        ));
    }

    function onBoardTest() public {
        require(offBoardResults.length > 0, "No offBoard results available");
        require(offBoardCombinedResults.length > 0, "No offBoardCombined results available");
        
        onBoardResults.push(MpcCore.decrypt(MpcCore.onBoard(offBoardResults[offBoardResults.length - 1])));
        onBoardResults.push(MpcCore.decrypt(
            MpcCore.onBoard(offBoardCombinedResults[offBoardCombinedResults.length - 1].ciphertext)
        ));
    }
}
