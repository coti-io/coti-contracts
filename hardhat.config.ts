import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  defaultNetwork: "devnet",
  solidity: "0.8.20",
  networks: {
    devnet: {
      url: "https://devnet.coti.io/rpc",
      chainId: 13068200,
    },
  }
}

export default config;
