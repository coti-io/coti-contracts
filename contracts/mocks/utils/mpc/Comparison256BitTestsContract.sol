// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract Comparison256BitTestsContract {

    bool[] public boolResults;
    uint256[] public uintResults2;

    function eqTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetBools(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            boolResults[i] = MpcCore.decrypt(MpcCore.eq(gtA, gtB));

            assert(boolResults[i] == MpcCore.decrypt(MpcCore.eq(a[i], gtB)));
            assert(boolResults[i] == MpcCore.decrypt(MpcCore.eq(gtA, b[i])));
        }
    }

    function neTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetBools(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            boolResults[i] = MpcCore.decrypt(MpcCore.ne(gtA, gtB));

            assert(boolResults[i] == MpcCore.decrypt(MpcCore.ne(a[i], gtB)));
            assert(boolResults[i] == MpcCore.decrypt(MpcCore.ne(gtA, b[i])));
        }
    }

    function geTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetBools(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            boolResults[i] = MpcCore.decrypt(MpcCore.ge(gtA, gtB));

            assert(boolResults[i] == MpcCore.decrypt(MpcCore.ge(a[i], gtB)));
            assert(boolResults[i] == MpcCore.decrypt(MpcCore.ge(gtA, b[i])));
        }
    }

    function gtTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetBools(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            boolResults[i] = MpcCore.decrypt(MpcCore.gt(gtA, gtB));

            assert(boolResults[i] == MpcCore.decrypt(MpcCore.gt(a[i], gtB)));
            assert(boolResults[i] == MpcCore.decrypt(MpcCore.gt(gtA, b[i])));
        }
    }

    function leTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetBools(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            boolResults[i] = MpcCore.decrypt(MpcCore.le(gtA, gtB));

            assert(boolResults[i] == MpcCore.decrypt(MpcCore.le(a[i], gtB)));
            assert(boolResults[i] == MpcCore.decrypt(MpcCore.le(gtA, b[i])));
        }
    }

    function ltTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetBools(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            boolResults[i] = MpcCore.decrypt(MpcCore.lt(gtA, gtB));

            assert(boolResults[i] == MpcCore.decrypt(MpcCore.lt(a[i], gtB)));
            assert(boolResults[i] == MpcCore.decrypt(MpcCore.lt(gtA, b[i])));
        }
    }

    function minTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            uintResults2[i] = MpcCore.decrypt(MpcCore.min(gtA, gtB));

            assert(uintResults2[i] == MpcCore.decrypt(MpcCore.min(a[i], gtB)));
            assert(uintResults2[i] == MpcCore.decrypt(MpcCore.min(gtA, b[i])));
        }
    }

    function maxTest(uint256[] calldata a, uint256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers2(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtUint256 memory gtA = MpcCore.setPublic256(a[i]);
            gtUint256 memory gtB = MpcCore.setPublic256(b[i]);
            
            uintResults2[i] = MpcCore.decrypt(MpcCore.max(gtA, gtB));

            assert(uintResults2[i] == MpcCore.decrypt(MpcCore.max(a[i], gtB)));
            assert(uintResults2[i] == MpcCore.decrypt(MpcCore.max(gtA, b[i])));
        }
    }

    function _resetBools(uint256 length) internal {
        // Reset the booleans array
        delete boolResults;
        
        // Resize the booleans array to match input length
        for(uint i = 0; i < length; i++) {
            boolResults.push(false);
        }
    }

    function _resetNumbers2(uint256 length) internal {
        // Reset the numbers array
        delete uintResults2;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            uintResults2.push(0);
        }
    }
}