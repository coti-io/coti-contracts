# PrivateERC721

## Overview

`PrivateERC721` is an abstract implementation of the [ERC721 Non-Fungible Token (NFT) Standard](https://eips.ethereum.org/EIPS/eip-721). It includes essential features of the standard, such as token ownership, approval, transfers, and safe transfers. This contract implements key components of the ERC721 standard while maintaining support for token metadata, but without fully implementing the metadata extension.

## Prerequisites

- **Solidity Version**: `^0.8.19`
- **License**: MIT
- **Dependencies**:
  - OpenZeppelin’s `Context`, `ERC165`, and `IERC721` contracts.
  - `IERC721Receiver` for safe transfer checks.
  - `IERC721Errors` interface for custom errors (related to the draft standard [IERC6093](https://eips.ethereum.org/EIPS/eip-6093)).

## Table of Contents
- [Events](#events)
- [State Variables](#state-variables)
- [Constructor](#constructor)
- [Functions](#functions)
  - [Supports Interface](#supports-interface)
  - [Balance Of](#balance-of)
  - [Owner Of](#owner-of)
  - [Name](#name)
  - [Symbol](#symbol)
  - [Approve](#approve)
  - [Get Approved](#get-approved)
  - [Set Approval For All](#set-approval-for-all)
  - [Is Approved For All](#is-approved-for-all)
  - [Transfer From](#transfer-from)
  - [Safe Transfer From](#safe-transfer-from)
  - [Private/Internal Functions](#privateinternal-functions)

## Events

## Event: `Transfer`

```solidity
event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
```

### Description:
This event is emitted whenever an ERC-721 token is transferred from one address to another. It occurs during both direct token transfers (`transferFrom`) and safe token transfers (`safeTransferFrom`). This event helps external observers, such as dApps and explorers, to track the movement of tokens.

### Parameters:
- **`from`** (`address`): The address of the current owner of the token.
- **`to`** (`address`): The address that is receiving ownership of the token.
- **`tokenId`** (`uint256`): The unique identifier (ID) of the token being transferred.

### Important Notes:
- This event is emitted for both `transferFrom` and `safeTransferFrom` operations.
- If a token is minted, `from` will be the zero address (`address(0)`).
- If a token is burned, `to` will be the zero address (`address(0)`).

## Event: `Approval`

```solidity
event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
```

### Description:
The `Approval` event is emitted when an owner grants or revokes permission to another account (the `approved` address) to transfer a specific token. Each ERC-721 token can only have one approved address at a time. The approval is reset when the token is transferred to a new owner.

### Parameters:
- **`owner`** (`address`): The current owner of the token.
- **`approved`** (`address`): The address that is approved to transfer the token. This can be the zero address (`address(0)`) if no account is approved.
- **`tokenId`** (`uint256`): The unique identifier (ID) of the token being approved for transfer.

### Important Notes:
- This event is specific to individual tokens, meaning approvals apply to a single `tokenId`.
- Approving the zero address (`address(0)`) clears the previous approval, effectively revoking approval for that token.

## Event: `ApprovalForAll`

```solidity
event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
```

### Description:
This event is emitted when an owner enables or disables an operator to manage all of their assets. Operators can transfer or manage any token owned by the `owner`. The event allows for bulk approval of all tokens owned by a single account.

### Parameters:
- **`owner`** (`address`): The address of the token owner.
- **`operator`** (`address`): The address that is granted or revoked permission to manage all of the owner's tokens.
- **`approved`** (`bool`): A boolean value indicating whether the operator is approved (`true`) or approval is revoked (`false`).

### Important Notes:
- This event differs from the `Approval` event because it applies to all tokens owned by the `owner`, not a single token.
- This event is emitted when the `setApprovalForAll` function is called, allowing or revoking an operator’s access to all of the owner's tokens.

## State Variables

- **_name** (`string`): The name of the token collection.
- **_symbol** (`string`): The symbol for the token collection.
- **_owners** (`mapping(uint256 => address)`): Maps a token ID to its owner address.
- **_balances** (`mapping(address => uint256)`): Maps owner addresses to the number of tokens they own.
- **_tokenApprovals** (`mapping(uint256 => address)`): Maps a token ID to the approved address for that token.
- **_operatorApprovals** (`mapping(address => mapping(address => bool))`): Maps an owner to an operator, allowing the operator to manage all tokens owned by that owner.

## Constructor

```solidity
constructor(string memory name_, string memory symbol_)
```

The constructor initializes the contract by setting the name and symbol of the token collection. It accepts the following parameters:

- **`name_`**: The name of the token collection.
- **`symbol_`**: The symbol for the token collection.

## Functions

### Supports Interface

```solidity
function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool)
```

Implements the `supportsInterface` function to check if the contract implements a specific interface (e.g., `IERC721`).

- **`interfaceId`**: The interface identifier to check.
- **Returns**: `true` if the contract supports the interface, otherwise `false`.

### Balance Of

```solidity
function balanceOf(address owner) public view virtual returns (uint256)
```

Returns the number of tokens owned by the given address.

- **`owner`**: The address to query.
- **Returns**: The number of tokens owned by the address.
- **Reverts**: `ERC721InvalidOwner` if `owner` is the zero address.

### Owner Of

```solidity
function ownerOf(uint256 tokenId) public view virtual returns (address)
```

Returns the owner of the given `tokenId`.

- **`tokenId`**: The ID of the token.
- **Returns**: The owner address of the `tokenId`.
- **Reverts**: If the token does not exist.

### Name

```solidity
function name() public view virtual returns (string memory)
```

Returns the name of the token collection.

### Symbol

```solidity
function symbol() public view virtual returns (string memory)
```

Returns the symbol of the token collection.

### Approve

```solidity
function approve(address to, uint256 tokenId) public virtual
```

Approves the given address (`to`) to transfer the specified token on behalf of the owner.

- **`to`**: The address to be approved.
- **`tokenId`**: The ID of the token to approve.

### Get Approved

```solidity
function getApproved(uint256 tokenId) public view virtual returns (address)
```

Returns the approved address for the given `tokenId`.

- **`tokenId`**: The ID of the token to check.
- **Returns**: The address approved to transfer the `tokenId`.

### Set Approval For All

```solidity
function setApprovalForAll(address operator, bool approved) public virtual
```

Enables or disables approval for a third-party `operator` to manage all tokens owned by the sender.

- **`operator`**: The address of the operator.
- **`approved`**: `true` to approve, `false` to revoke approval.

### Is Approved For All

```solidity
function isApprovedForAll(address owner, address operator) public view virtual returns (bool)
```

Checks if the `operator` is approved to manage all tokens owned by `owner`.

- **`owner`**: The address of the token owner.
- **`operator`**: The address of the operator.
- **Returns**: `true` if the operator is approved, otherwise `false`.

### Transfer From

```solidity
function transferFrom(address from, address to, uint256 tokenId) public virtual
```

Transfers ownership of the `tokenId` from one address to another.

- **`from`**: The current owner of the token.
- **`to`**: The address receiving the token.
- **`tokenId`**: The ID of the token.
- **Reverts**: `ERC721InvalidReceiver` if `to` is the zero address or if the sender is not authorized to transfer the token.

### Safe Transfer From

```solidity
function safeTransferFrom(address from, address to, uint256 tokenId) public
```

Safely transfers a `tokenId` from one address to another, ensuring the receiver can handle ERC721 tokens.

- **`from`**: The current owner of the token.
- **`to`**: The address receiving the token.
- **`tokenId`**: The ID of the token.

### Private/Internal Functions

#### `_ownerOf`

```solidity
function _ownerOf(uint256 tokenId) internal view virtual returns (address)
```

Internal function that returns the owner of the `tokenId`.

#### `_isAuthorized`

```solidity
function _isAuthorized(address owner, address spender, uint256 tokenId) internal view virtual returns (bool)
```

Checks if `spender` is authorized to manage `owner`'s token or the specific `tokenId`.

#### `_approve`

```solidity
function _approve(address to, uint256 tokenId, address auth, bool emitEvent) internal virtual
```

Approves the address `to` to manage the `tokenId`. Optionally emits the `Approval` event.

#### `_mint`

```solidity
function _mint(address to, uint256 tokenId) internal
```

Mints a new token with the given `tokenId` and transfers it to the address `to`.

#### `_burn`

```solidity
function _burn(uint256 tokenId) internal
```

Burns (destroys) the token with the given `tokenId`.

#### `_checkOnERC721Received`

```solidity
function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) private
```

Private function to invoke the `IERC721Receiver.onERC721Received` on the target address if it's a contract.