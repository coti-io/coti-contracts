# AccountOnboard

## Overview

The `AccountOnboard` contract is responsible for onboarding user accounts to the system, leveraging RSA public keys and AES encryption. During onboarding, the user's AES encryption key is emitted in an encrypted form. This contract interacts with a utility contract `MpcCore` to retrieve the user key.

## Prerequisites

- **Solidity Version**: `^0.8.19`
- **License**: MIT
- **Dependencies**:
  - Imports from `../utils/mpc/MpcCore.sol`.

## Table of Contents
- [Events](#events)
  - [AccountOnboarded](#accountonboarded)
- [Functions](#functions)
  - [onboardAccount](#onboardaccount)

## Events

### AccountOnboarded

This event is triggered when a new account is successfully onboarded. It logs the user's account information, including the sender's address and the AES encryption key in its encrypted form.

#### Parameters:
- **`_from`**: (`address`) The address of the account that initiated the onboarding process.
- **`userKey`**: (`bytes`) The user's AES encryption key, encrypted using RSA. This key must be decrypted before use.

```solidity
event AccountOnboarded(address indexed _from, bytes userKey);
```

## Functions

### onboardAccount

The `onboardAccount` function is responsible for onboarding a new user account. It takes an RSA public key and a signed hash of the key, verifies the credentials, and emits the encrypted AES key.

#### Function Definition:

```solidity
function onboardAccount(bytes calldata publicKey, bytes calldata signedEK) public;
```

#### Parameters:
- **`publicKey`**: (`bytes`) The RSA public key of the user. This is used to verify and generate the AES encryption key.
- **`signedEK`**: (`bytes`) A signed hash of the RSA public key, used to ensure the authenticity of the public key.

#### Logic:
1. Calls the external `MpcCore.getUserKey()` function to retrieve the user's AES encryption key using the provided RSA public key and its signed hash.
2. Emits the `AccountOnboarded` event, logging the caller's address and the encrypted AES key.

#### Example Usage:

```solidity
function onboardAccount(bytes calldata publicKey, bytes calldata signedEK) public {
    bytes memory accountKey = MpcCore.getUserKey(publicKey, signedEK);
    emit AccountOnboarded(msg.sender, accountKey);
}
```

### External Function Calls:
- **`MpcCore.getUserKey(publicKey, signedEK)`**:
  - Retrieves the user's AES encryption key, based on the RSA public key and signed hash.