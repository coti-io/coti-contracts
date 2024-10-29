# PrivateERC20

## Overview

The `PrivateERC20` contract is an abstract implementation of a privacy-enhanced ERC20 token. It introduces mechanisms for handling encrypted addresses and balances, allowing for more secure and private token transfers. This contract builds on top of OpenZeppelin's `Context` and the `IPrivateERC20` interface, and it integrates with the `MpcCore` library for secure multiparty computation (MPC).

## Prerequisites

- **Solidity Version**: `^0.8.19`
- **License**: MIT
- **Dependencies**:
  - OpenZeppelin's `Context` contract
  - Interface `IPrivateERC20`
  - Utility `MpcCore` for cryptographic operations.

## Table of Contents
- [Constants](#constants)
  - [MAX_UINT_64](#max_uint_64)
- [State Variables](#state-variables)
  - [Account Encryption Address Mapping](#account-encryption-address-mapping)
  - [Balance Mapping](#balance-mapping)
  - [Allowances Mapping](#allowances-mapping)
  - [Total Supply](#total-supply)
  - [Token Name and Symbol](#token-name-and-symbol)
- [Errors](#errors)
  - [ERC20InvalidSender](#erc20invalidsender)
  - [ERC20InvalidReceiver](#erc20invalidreceiver)
- [Functions](#functions)
  - To be documented as additional logic is discovered.

## Constants

### MAX_UINT_64

```solidity
uint64 private constant MAX_UINT_64 = type(uint64).max;
```

The constant `MAX_UINT_64` represents the maximum value of a 64-bit unsigned integer. This is used as a cap for various operations in the contract.

## State Variables

### Account Encryption Address Mapping

```solidity
mapping(address account => address) private _accountEncryptionAddress;
```

This mapping associates each account (public address) with an encryption address. The encryption address could be used for handling cryptographically secure operations involving private balances and transactions.

### Balance Mapping

```solidity
mapping(address account => utUint64) private _balances;
```

The `_balances` mapping keeps track of each account's token balance, but it uses a 64-bit unsigned integer (`utUint64`). This might be intended for scaling or privacy-preserving reasons.

### Allowances Mapping

```solidity
mapping(address account => mapping(address spender => Allowance)) private _allowances;
```

The `_allowances` mapping tracks the allowance that one account (`account`) has given to another account (`spender`). This is a standard ERC20 allowance mechanism with the added layer of the `Allowance` structure, which may handle encrypted or privacy-preserving amounts.

### Total Supply

```solidity
ctUint64 private _totalSupply;
```

The `_totalSupply` variable keeps track of the total number of tokens in existence. Like the `_balances` mapping, it uses a 64-bit unsigned integer (`ctUint64`).

### Token Name and Symbol

```solidity
string private _name;
string private _symbol;
```

These variables store the name and symbol of the token, following the ERC20 standard.

## Errors

### ERC20InvalidSender

```solidity
error ERC20InvalidSender(address sender);
```

The `ERC20InvalidSender` error is raised when an invalid sender address attempts to perform a token transfer. It logs the `sender` address that caused the failure.

### ERC20InvalidReceiver

```solidity
error ERC20InvalidReceiver(address receiver);
```

The `ERC20InvalidReceiver` error is raised when a transfer fails due to an invalid receiver address. It logs the `receiver` address that caused the failure.

## Functions

Functions in the contract are abstract or unimplemented in this fragment. These likely involve ERC20-style operations, such as `transfer`, `approve`, and `transferFrom`, but with privacy-preserving adjustments, including the handling of encrypted addresses and balances.