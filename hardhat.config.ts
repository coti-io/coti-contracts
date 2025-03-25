import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

import dotenv from "dotenv"
dotenv.config()

const config: HardhatUserConfig = {
  defaultNetwork: "coti-testnet",
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 10000
      },
      metadata: {
        // do not include the metadata hash, since this is machine dependent
        // and we want all generated code to be deterministic
        // https://docs.soliditylang.org/en/v0.7.6/metadata.html
        bytecodeHash: 'none',
      },
    }
  },
  networks: {
    "coti-testnet": {
      url: "https://testnet.coti.io/rpc",
      chainId: 7082400,
    },
    "coti-mainnet": {
      url: "https://mainnet.coti.io/rpc",
      chainId: 2632500,
    },
  },
  mocha: {
    timeout: 100000000
  },
}

export default config;
