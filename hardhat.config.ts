import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

import dotenv from "dotenv"
dotenv.config()

const config: HardhatUserConfig = {
  defaultNetwork: "testnet",
  solidity: "0.8.20",
  networks: {
    testnet: {
      url: "https://testnet.coti.io/rpc",
      chainId: 7082400,
    },
  },
  mocha: {
    timeout: 100000000
  },
}

export default config;
