// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract ArithmeticSigned256BitTestsContract {

    bool[] public overflows;
    int256[] public numbers;

    function addTest(int256[] calldata a, int256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtInt256 gtA = MpcCore.setPublic256(a[i]);
            gtInt256 gtB = MpcCore.setPublic256(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.add(gtA, gtB));
        }
    }   

    function subTest(int256[] calldata a, int256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtInt256 gtA = MpcCore.setPublic256(a[i]);
            gtInt256 gtB = MpcCore.setPublic256(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.sub(gtA, gtB));
        }
    }

    function mulTest(int256[] calldata a, int256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtInt256 gtA = MpcCore.setPublic256(a[i]);
            gtInt256 gtB = MpcCore.setPublic256(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.mul(gtA, gtB));
        }
    }

    function divTest(int256[] calldata a, int256[] calldata b) public {
        require(a.length == b.length, "Input length mismatch");
        
        _resetNumbers(a.length);

        for (uint256 i = 0; i < a.length; ++i) {
            gtInt256 gtA = MpcCore.setPublic256(a[i]);
            gtInt256 gtB = MpcCore.setPublic256(b[i]);
            
            numbers[i] = MpcCore.decrypt(MpcCore.div(gtA, gtB));
        }
    }

    function _resetNumbers(uint256 length) internal {
        // Reset the numbers array
        delete numbers;
        
        // Resize the numbers array to match input length
        for(uint i = 0; i < length; i++) {
            numbers.push(0);
        }
    }
}