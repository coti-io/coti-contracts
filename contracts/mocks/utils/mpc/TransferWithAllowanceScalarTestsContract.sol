// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract TransferWithAllowanceScalarTestsContract {

    struct AllGTCastingValues {
        gtUint8 a8_s;
        gtUint8 b8_s;
        gtUint16 a16_s;
        gtUint16 b16_s;
        gtUint32 a32_s;
        gtUint32 b32_s;
        gtUint64 a64_s;
        gtUint64 b64_s;
    }

    struct AllAmountValues {
        uint8 amount8_s;
        uint16 amount16_s;
        uint32 amount32_s;
        uint64 amount64_s;
    }

    struct AllAllowanceValues {
        gtUint8 allowance8_s;
        gtUint16 allowance16_s;
        gtUint32 allowance32_s;
        gtUint64 allowance64_s;
        uint8 allowance;
    }

    uint8 newA;
    uint8 newB;
    bool res;
    uint8 newAllowance;

    function getResults() public view returns (uint8, uint8, bool, uint8) {
        return (newA, newB, res, newAllowance);
    }

    function computeAndCheckTransfer16(
        AllGTCastingValues memory allGTCastingValues,
        AllAmountValues memory allAmountValues,
        AllAllowanceValues memory allAllowanceValues
    )
        public
    {

        // Check all options for casting to 16 while amount is scalar
        (gtUint16 newA_s, gtUint16 newB_s, gtBool res_s, gtUint16 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b8_s, allAmountValues.amount16_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b16_s, allAmountValues.amount16_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b8_s, allAmountValues.amount16_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");
    }

    function computeAndCheckTransfer32(
        AllGTCastingValues memory allGTCastingValues,
        AllAmountValues memory allAmountValues,
        AllAllowanceValues memory allAllowanceValues
    ) public {

        // Check all options for casting to 32 while amount is scalar
        (gtUint32 newA_s, gtUint32 newB_s, gtBool res_s, gtUint32 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b8_s, allAmountValues.amount32_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b16_s, allAmountValues.amount32_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b8_s, allAmountValues.amount32_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b16_s, allAmountValues.amount32_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b8_s, allAmountValues.amount32_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b32_s, allAmountValues.amount32_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b16_s, allAmountValues.amount32_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");
    }

    function computeAndCheckTransfer64(
        AllGTCastingValues memory allGTCastingValues,
        AllAmountValues memory allAmountValues,
        AllAllowanceValues memory allAllowanceValues
    ) public {

        // Check all options for casting to 64 while amount is scalar
        (gtUint64 newA_s, gtUint64 newB_s, gtBool res_s, gtUint64 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount64_s, allAllowanceValues.allowance64_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount64_s, allAllowanceValues.allowance8_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount64_s, allAllowanceValues.allowance16_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b8_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a16_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b16_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a32_s, allGTCastingValues.b64_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");

        (newA_s, newB_s, res_s, newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a64_s, allGTCastingValues.b32_s, allAmountValues.amount64_s, allAllowanceValues.allowance32_s);
        require(newA == MpcCore.decrypt(newA_s) && newB == MpcCore.decrypt(newB_s) && res == MpcCore.decrypt(res_s) && newAllowance == MpcCore.decrypt(newAllowance_s), "transferTest: check scalar failed");
    }


    function transferWithAllowanceScalarTest(uint8 a, uint8 b, uint8 amount, uint8 allowance) public returns (uint8, uint8, bool, uint8) {
        AllGTCastingValues memory allGTCastingValues;
        AllAmountValues memory allAmountValues;
        AllAllowanceValues memory allAllowanceValues;
        allGTCastingValues.a8_s = MpcCore.setPublic8(a);
        allGTCastingValues.b8_s = MpcCore.setPublic8(b);
        allGTCastingValues.a16_s =  MpcCore.setPublic16(a);
        allGTCastingValues.b16_s =  MpcCore.setPublic16(b);
        allGTCastingValues.a32_s =  MpcCore.setPublic32(a);
        allGTCastingValues.b32_s =  MpcCore.setPublic32(b);
        allGTCastingValues.a64_s =  MpcCore.setPublic64(a);
        allGTCastingValues.b64_s =  MpcCore.setPublic64(b);
        allAmountValues.amount8_s = amount;
        allAmountValues.amount16_s = uint16(amount);
        allAmountValues.amount32_s = uint32(amount);
        allAmountValues.amount64_s = uint64(amount);
        allAllowanceValues.allowance8_s = MpcCore.setPublic8(allowance);
        allAllowanceValues.allowance16_s = MpcCore.setPublic16(allowance);
        allAllowanceValues.allowance32_s = MpcCore.setPublic32(allowance);
        allAllowanceValues.allowance64_s = MpcCore.setPublic64(allowance);
        allAllowanceValues.allowance = allowance;

        // Calculate the expected result
        (gtUint8 newA_s, gtUint8 newB_s, gtBool res_s, gtUint8 newAllowance_s) = MpcCore.transferWithAllowance(allGTCastingValues.a8_s, allGTCastingValues.b8_s, amount, allAllowanceValues.allowance8_s);
        newA =  MpcCore.decrypt(newA_s);
        newB =  MpcCore.decrypt(newB_s);
        res =  MpcCore.decrypt(res_s);
        newAllowance =  MpcCore.decrypt(newAllowance_s);


        // Calculate the result with casting to 16
        computeAndCheckTransfer16(allGTCastingValues, allAmountValues, allAllowanceValues);

        // Calculate the result with casting to 32
        computeAndCheckTransfer32(allGTCastingValues, allAmountValues, allAllowanceValues);

        // Calculate the result with casting to 64
        computeAndCheckTransfer64(allGTCastingValues, allAmountValues, allAllowanceValues);

        return (newA, newB, res, newAllowance);
    }

}
