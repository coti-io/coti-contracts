import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-verify";

import dotenv from "dotenv"
dotenv.config()

const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

const config: HardhatUserConfig = {
  defaultNetwork: "coti-testnet",
  solidity: {
    compilers: [
      {
        version: "0.8.20",
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
      {
        version: "0.8.19",
        settings: {
          optimizer: {
            enabled: true,
            runs: 10000
          },
          metadata: {
            bytecodeHash: 'none',
          },
        }
      }
    ]
  },
  networks: {
    "coti-testnet": {
      url: "https://testnet.coti.io/rpc",
      chainId: 7082400,
      accounts,
    },
    "coti-mainnet": {
      url: "https://mainnet.coti.io/rpc",
      chainId: 2632500,
      accounts,
    },
  },
  etherscan: {
    apiKey: {
      "coti-testnet": "placeholder",
      "coti-mainnet": "placeholder",
    },
    customChains: [
      {
        network: "coti-testnet",
        chainId: 7082400,
        urls: {
          apiURL: "https://testnet.cotiscan.io/api",
          browserURL: "https://testnet.cotiscan.io/",
        },
      },
      {
        network: "coti-mainnet",
        chainId: 2632500,
        urls: {
          apiURL: "https://cotiscan.io/api",
          browserURL: "https://cotiscan.io/",
        },
      },
    ],
  },
  mocha: {
    timeout: 100000000
  },
}

export default config;
