# COTI Contracts

A library for smart contract development on the COTI network.

> [!NOTE]
> This repository is meant to replace the now-deprecated [confidentiality-contracts](https://github.com/coti-io/confidentiality-contracts) repository.

#### Important Links

[Docs](https://docs.coti.io) | [Discord](https://discord.gg/cuCykh8P4m) | [Faucet](https://faucet.coti.io)

#### Network-Specific Links

[Devnet Explorer](https://explorer-devnet.coti.io) | [Testnet Explorer](https://testnet.cotiscan.io)

## Overview

> [!NOTE]  
> Due to the nature of ongoing development, future versions might break existing functionality

The following contracts are included in the library:
- [DataPrivacyFramework](/contracts/access/DataPrivacyFramework/)
- [AccountOnboard](/contracts/onboard/)
- [PrivateERC20](/contracts/token/PrivateERC20/)
- [PrivateERC721](/contracts/token/PrivateERC721/)
- [MpcCore](/contracts/utils/mpc/)

### Installation

#### Hardhat (npm)

```bash
npm install @coti-io/coti-contracts
```

### Usage

Once installed, you can use the contracts in the library by importing them:

```solidity
pragma solidity ^0.8.20;

import {PrivateERC20} from "@coti-io/coti-contracts/token/PrivateERC20/PrivateERC20.sol";

contract MyToken is PrivateERC20 {
    constructor() ERC721("MyToken", "MTOK") {}
}
```
