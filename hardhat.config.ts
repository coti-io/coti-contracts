import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-verify";

import dotenv from "dotenv"
dotenv.config()

/** Bump estimated gas price / EIP-1559 fees by 30% on COTI networks (see hardhat/gasPriceBump.ts). */
import "./hardhat/gasPriceBump"
/** Prefer native solc on linux-arm64 (solcjs OOMs on large viaIR inputs). */
import "./hardhat/nativeSolcArm64"

const accounts = process.env.PRIVATE_KEY
  ? [process.env.PRIVATE_KEY]
  : process.env.SIGNING_KEYS
    ? process.env.SIGNING_KEYS.split(",").map((k) => k.trim()).filter(Boolean)
    : [];

const config: HardhatUserConfig = {
  defaultNetwork: "coti-testnet",
  // Pinned compiler versions for reproducible bytecode; bump only alongside contract pragma / CI review.
  solidity: {
    compilers: [
      {
        version: "0.8.28",
        settings: {
          // COTI rejects Shanghai PUSH0; keep Paris for deployability.
          evmVersion: "paris",
          viaIR: true,
          optimizer: {
            enabled: true,
            // Prefer create-size headroom under the 24_576-byte Spurious Dragon limit (higher runs → larger code).
            runs: 200,
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
        // Exact-pragma legacy contracts (e.g. disperse).
        version: "0.8.20",
        settings: {
          evmVersion: "paris",
          viaIR: true,
          optimizer: {
            enabled: true,
            runs: 200,
          },
          metadata: {
            bytecodeHash: 'none',
          },
        }
      },
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
          apiURL: "https://mainnet.cotiscan.io/api",
          browserURL: "https://mainnet.cotiscan.io/",
        },
      },
    ],
  },
  mocha: {
    timeout: 100000000
  },
}

export default config;
