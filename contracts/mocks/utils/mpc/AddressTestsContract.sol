// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../../utils/mpc/MpcCore.sol";

contract AddressTestsContract {

    bool public isEqual;

    // Encrypted address variables

    ctAddress public userEncryptedAddress;

    ctAddress public networkEncryptedAddress;

    address public plaintextAddress;

    // Encrypted address function

    function setUserEncryptedAddress(itAddress calldata it_) public {
        gtAddress memory gt_ = MpcCore.validateCiphertext(it_);

        userEncryptedAddress = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    function setNetworkEncryptedAddress(itAddress calldata it_) public {
        gtAddress memory gt_ = MpcCore.validateCiphertext(it_);

        networkEncryptedAddress = MpcCore.offBoard(gt_);
    }

    function decryptNetworkEncryptedAddress() public {
        gtAddress memory gt_ = MpcCore.onBoard(networkEncryptedAddress);

        plaintextAddress = MpcCore.decrypt(gt_);
    }

    function setPublicAddress(address addr) public {
        gtAddress memory gt_ = MpcCore.setPublicAddress(addr);

        userEncryptedAddress = MpcCore.offBoardToUser(gt_, msg.sender);
    }

    function setIsEqual(itAddress calldata a_, itAddress calldata b_, bool useEq) public {
        gtAddress memory a = MpcCore.validateCiphertext(a_);
        gtAddress memory b = MpcCore.validateCiphertext(b_);

        gtBool isEqual_;

        if (useEq) {
            isEqual_ = MpcCore.eq(a, b);
        } else {
            isEqual_ = MpcCore.not(MpcCore.ne(a, b));
        }

        isEqual = MpcCore.decrypt(isEqual_);
    }

    function setRandomAddress() public {
        gtAddress memory gt_ = MpcCore.randAddress();

        userEncryptedAddress = MpcCore.offBoardToUser(gt_, msg.sender);
    }
}