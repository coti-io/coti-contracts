// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./utils/mpc/MpcCore.sol";

contract Mul128 {

    uint64 public result0;
    uint64 public result1;

    function _mul64(gtUint64 a, gtUint64 b) private returns (gtUint64, gtUint64) {
        gtUint64 MAX_UINT32 = MpcCore.setPublic64(type(uint32).max);

        gtUint64 pp0;
        gtUint64 pp1;
        gtUint64 pp2;
        gtUint64 pp3;

        {
            // Split the numbers into 32-bit parts
            gtUint64 aLow = MpcCore.and(a, MAX_UINT32);
            gtUint64 aHigh = MpcCore.shr(a, 32);
            gtUint64 bLow = MpcCore.and(b, MAX_UINT32);
            gtUint64 bHigh = MpcCore.shr(b, 32);

            // Compute partial products
            pp0 = MpcCore.mul(aLow, bLow);
            pp1 = MpcCore.mul(aLow, bHigh);
            pp2 = MpcCore.mul(aHigh, bLow);
            pp3 = MpcCore.mul(aHigh, bHigh);
        }

        // Compute high and low parts
        gtUint64 mid = MpcCore.add(
            MpcCore.add(
                MpcCore.shr(pp0, 32),
                MpcCore.and(pp1, MAX_UINT32)
            ),
            MpcCore.and(pp2, MAX_UINT32)
        );
        gtUint64 carry = MpcCore.shr(mid, 32);

        gtUint64 high = MpcCore.add(
            MpcCore.add(pp3, MpcCore.shr(pp1, 32)),
            MpcCore.add(MpcCore.shr(pp2, 32), carry)
        );
        gtUint64 low = MpcCore.or(
            MpcCore.and(pp0, MAX_UINT32),
            MpcCore.shl(MpcCore.and(mid, MAX_UINT32), 32)
        );

        return (high, low);
    }

    function mul(gtUint128 memory a, gtUint128 memory b) internal returns (gtUint128 memory) {
        gtUint128 memory result;

        // Compute partial products
        (gtUint64 pp0, gtUint64 low) = _mul64(a.low, b.low);
        (, gtUint64 pp1) = _mul64(a.high, b.low);
        (, gtUint64 pp2) = _mul64(a.low, b.high);

        // Compute the high and low parts
        result.high = MpcCore.add(
            MpcCore.add(pp0, pp1),
            pp2
        );
        result.low = low;
        
        return result;
    }

    function test(uint128 a, uint128 b) public {
        gtUint128 memory gtA = MpcCore.setPublic128(a);
        gtUint128 memory gtB = MpcCore.setPublic128(b);

        (gtUint64 pp0, gtUint64 low) = _mul64(gtA.low, gtB.low);
        (, gtUint64 pp1) = _mul64(gtA.high, gtB.low);
        (, gtUint64 pp2) = _mul64(gtA.low, gtB.high);

        gtUint64 high = MpcCore.add(pp0, MpcCore.add(pp1, pp2));

        result0 = MpcCore.decrypt(high);
        result1 = MpcCore.decrypt(low);
    }
}