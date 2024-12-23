/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { ethers } from "ethers";
import {
  DeployContractOptions,
  FactoryOptions,
  HardhatEthersHelpers as HardhatEthersHelpersBase,
} from "@nomicfoundation/hardhat-ethers/types";

import * as Contracts from ".";

declare module "hardhat/types/runtime" {
  interface HardhatEthersHelpers extends HardhatEthersHelpersBase {
    getContractFactory(
      name: "IERC1155Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC1155Errors__factory>;
    getContractFactory(
      name: "IERC20Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Errors__factory>;
    getContractFactory(
      name: "IERC721Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Errors__factory>;
    getContractFactory(
      name: "IERC4906",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC4906__factory>;
    getContractFactory(
      name: "IERC721",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721__factory>;
    getContractFactory(
      name: "IERC721Receiver",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Receiver__factory>;
    getContractFactory(
      name: "ERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC165__factory>;
    getContractFactory(
      name: "IERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC165__factory>;
    getContractFactory(
      name: "DataPrivacyFramework",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.DataPrivacyFramework__factory>;
    getContractFactory(
      name: "DataPrivacyFrameworkMpc",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.DataPrivacyFrameworkMpc__factory>;
    getContractFactory(
      name: "DataPrivacyFrameworkMock",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.DataPrivacyFrameworkMock__factory>;
    getContractFactory(
      name: "PrivateERC20Mock",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.PrivateERC20Mock__factory>;
    getContractFactory(
      name: "PrivateERC721URIStorageMock",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.PrivateERC721URIStorageMock__factory>;
    getContractFactory(
      name: "ArithmeticTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ArithmeticTestsContract__factory>;
    getContractFactory(
      name: "BitwiseTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.BitwiseTestsContract__factory>;
    getContractFactory(
      name: "Comparison1TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Comparison1TestsContract__factory>;
    getContractFactory(
      name: "Comparison2TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Comparison2TestsContract__factory>;
    getContractFactory(
      name: "MinMaxTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.MinMaxTestsContract__factory>;
    getContractFactory(
      name: "Miscellaneous1TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Miscellaneous1TestsContract__factory>;
    getContractFactory(
      name: "MiscellaneousTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.MiscellaneousTestsContract__factory>;
    getContractFactory(
      name: "OffboardToUserKeyTestContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.OffboardToUserKeyTestContract__factory>;
    getContractFactory(
      name: "StringTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.StringTestsContract__factory>;
    getContractFactory(
      name: "TransferScalarTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferScalarTestsContract__factory>;
    getContractFactory(
      name: "TransferTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferTestsContract__factory>;
    getContractFactory(
      name: "TransferWithAllowance64_16TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferWithAllowance64_16TestsContract__factory>;
    getContractFactory(
      name: "TransferWithAllowance64_32TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferWithAllowance64_32TestsContract__factory>;
    getContractFactory(
      name: "TransferWithAllowance64_64TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferWithAllowance64_64TestsContract__factory>;
    getContractFactory(
      name: "TransferWithAllowance64_8TestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferWithAllowance64_8TestsContract__factory>;
    getContractFactory(
      name: "TransferWithAllowanceScalarTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferWithAllowanceScalarTestsContract__factory>;
    getContractFactory(
      name: "TransferWithAllowanceTestsContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TransferWithAllowanceTestsContract__factory>;
    getContractFactory(
      name: "PrivateERC20WalletMock",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.PrivateERC20WalletMock__factory>;
    getContractFactory(
      name: "AccountOnboard",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccountOnboard__factory>;
    getContractFactory(
      name: "IPrivateERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IPrivateERC20__factory>;
    getContractFactory(
      name: "PrivateERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.PrivateERC20__factory>;
    getContractFactory(
      name: "PrivateERC721URIStorage",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.PrivateERC721URIStorage__factory>;
    getContractFactory(
      name: "PrivateERC721",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.PrivateERC721__factory>;
    getContractFactory(
      name: "MpcCore",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.MpcCore__factory>;
    getContractFactory(
      name: "ExtendedOperations",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ExtendedOperations__factory>;

    getContractAt(
      name: "IERC1155Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC1155Errors>;
    getContractAt(
      name: "IERC20Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20Errors>;
    getContractAt(
      name: "IERC721Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC721Errors>;
    getContractAt(
      name: "IERC4906",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC4906>;
    getContractAt(
      name: "IERC721",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC721>;
    getContractAt(
      name: "IERC721Receiver",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC721Receiver>;
    getContractAt(
      name: "ERC165",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ERC165>;
    getContractAt(
      name: "IERC165",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC165>;
    getContractAt(
      name: "DataPrivacyFramework",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.DataPrivacyFramework>;
    getContractAt(
      name: "DataPrivacyFrameworkMpc",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.DataPrivacyFrameworkMpc>;
    getContractAt(
      name: "DataPrivacyFrameworkMock",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.DataPrivacyFrameworkMock>;
    getContractAt(
      name: "PrivateERC20Mock",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.PrivateERC20Mock>;
    getContractAt(
      name: "PrivateERC721URIStorageMock",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.PrivateERC721URIStorageMock>;
    getContractAt(
      name: "ArithmeticTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ArithmeticTestsContract>;
    getContractAt(
      name: "BitwiseTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.BitwiseTestsContract>;
    getContractAt(
      name: "Comparison1TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Comparison1TestsContract>;
    getContractAt(
      name: "Comparison2TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Comparison2TestsContract>;
    getContractAt(
      name: "MinMaxTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.MinMaxTestsContract>;
    getContractAt(
      name: "Miscellaneous1TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Miscellaneous1TestsContract>;
    getContractAt(
      name: "MiscellaneousTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.MiscellaneousTestsContract>;
    getContractAt(
      name: "OffboardToUserKeyTestContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.OffboardToUserKeyTestContract>;
    getContractAt(
      name: "StringTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.StringTestsContract>;
    getContractAt(
      name: "TransferScalarTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferScalarTestsContract>;
    getContractAt(
      name: "TransferTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferTestsContract>;
    getContractAt(
      name: "TransferWithAllowance64_16TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferWithAllowance64_16TestsContract>;
    getContractAt(
      name: "TransferWithAllowance64_32TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferWithAllowance64_32TestsContract>;
    getContractAt(
      name: "TransferWithAllowance64_64TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferWithAllowance64_64TestsContract>;
    getContractAt(
      name: "TransferWithAllowance64_8TestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferWithAllowance64_8TestsContract>;
    getContractAt(
      name: "TransferWithAllowanceScalarTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferWithAllowanceScalarTestsContract>;
    getContractAt(
      name: "TransferWithAllowanceTestsContract",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TransferWithAllowanceTestsContract>;
    getContractAt(
      name: "PrivateERC20WalletMock",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.PrivateERC20WalletMock>;
    getContractAt(
      name: "AccountOnboard",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AccountOnboard>;
    getContractAt(
      name: "IPrivateERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IPrivateERC20>;
    getContractAt(
      name: "PrivateERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.PrivateERC20>;
    getContractAt(
      name: "PrivateERC721URIStorage",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.PrivateERC721URIStorage>;
    getContractAt(
      name: "PrivateERC721",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.PrivateERC721>;
    getContractAt(
      name: "MpcCore",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.MpcCore>;
    getContractAt(
      name: "ExtendedOperations",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ExtendedOperations>;

    deployContract(
      name: "IERC1155Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1155Errors>;
    deployContract(
      name: "IERC20Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Errors>;
    deployContract(
      name: "IERC721Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Errors>;
    deployContract(
      name: "IERC4906",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC4906>;
    deployContract(
      name: "IERC721",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721>;
    deployContract(
      name: "IERC721Receiver",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Receiver>;
    deployContract(
      name: "ERC165",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC165>;
    deployContract(
      name: "IERC165",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC165>;
    deployContract(
      name: "DataPrivacyFramework",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DataPrivacyFramework>;
    deployContract(
      name: "DataPrivacyFrameworkMpc",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DataPrivacyFrameworkMpc>;
    deployContract(
      name: "DataPrivacyFrameworkMock",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DataPrivacyFrameworkMock>;
    deployContract(
      name: "PrivateERC20Mock",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC20Mock>;
    deployContract(
      name: "PrivateERC721URIStorageMock",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC721URIStorageMock>;
    deployContract(
      name: "ArithmeticTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ArithmeticTestsContract>;
    deployContract(
      name: "BitwiseTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.BitwiseTestsContract>;
    deployContract(
      name: "Comparison1TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Comparison1TestsContract>;
    deployContract(
      name: "Comparison2TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Comparison2TestsContract>;
    deployContract(
      name: "MinMaxTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.MinMaxTestsContract>;
    deployContract(
      name: "Miscellaneous1TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Miscellaneous1TestsContract>;
    deployContract(
      name: "MiscellaneousTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.MiscellaneousTestsContract>;
    deployContract(
      name: "OffboardToUserKeyTestContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.OffboardToUserKeyTestContract>;
    deployContract(
      name: "StringTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.StringTestsContract>;
    deployContract(
      name: "TransferScalarTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferScalarTestsContract>;
    deployContract(
      name: "TransferTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferTestsContract>;
    deployContract(
      name: "TransferWithAllowance64_16TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_16TestsContract>;
    deployContract(
      name: "TransferWithAllowance64_32TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_32TestsContract>;
    deployContract(
      name: "TransferWithAllowance64_64TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_64TestsContract>;
    deployContract(
      name: "TransferWithAllowance64_8TestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_8TestsContract>;
    deployContract(
      name: "TransferWithAllowanceScalarTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowanceScalarTestsContract>;
    deployContract(
      name: "TransferWithAllowanceTestsContract",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowanceTestsContract>;
    deployContract(
      name: "PrivateERC20WalletMock",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC20WalletMock>;
    deployContract(
      name: "AccountOnboard",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountOnboard>;
    deployContract(
      name: "IPrivateERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IPrivateERC20>;
    deployContract(
      name: "PrivateERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC20>;
    deployContract(
      name: "PrivateERC721URIStorage",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC721URIStorage>;
    deployContract(
      name: "PrivateERC721",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC721>;
    deployContract(
      name: "MpcCore",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.MpcCore>;
    deployContract(
      name: "ExtendedOperations",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ExtendedOperations>;

    deployContract(
      name: "IERC1155Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1155Errors>;
    deployContract(
      name: "IERC20Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Errors>;
    deployContract(
      name: "IERC721Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Errors>;
    deployContract(
      name: "IERC4906",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC4906>;
    deployContract(
      name: "IERC721",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721>;
    deployContract(
      name: "IERC721Receiver",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Receiver>;
    deployContract(
      name: "ERC165",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC165>;
    deployContract(
      name: "IERC165",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC165>;
    deployContract(
      name: "DataPrivacyFramework",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DataPrivacyFramework>;
    deployContract(
      name: "DataPrivacyFrameworkMpc",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DataPrivacyFrameworkMpc>;
    deployContract(
      name: "DataPrivacyFrameworkMock",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.DataPrivacyFrameworkMock>;
    deployContract(
      name: "PrivateERC20Mock",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC20Mock>;
    deployContract(
      name: "PrivateERC721URIStorageMock",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC721URIStorageMock>;
    deployContract(
      name: "ArithmeticTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ArithmeticTestsContract>;
    deployContract(
      name: "BitwiseTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.BitwiseTestsContract>;
    deployContract(
      name: "Comparison1TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Comparison1TestsContract>;
    deployContract(
      name: "Comparison2TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Comparison2TestsContract>;
    deployContract(
      name: "MinMaxTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.MinMaxTestsContract>;
    deployContract(
      name: "Miscellaneous1TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Miscellaneous1TestsContract>;
    deployContract(
      name: "MiscellaneousTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.MiscellaneousTestsContract>;
    deployContract(
      name: "OffboardToUserKeyTestContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.OffboardToUserKeyTestContract>;
    deployContract(
      name: "StringTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.StringTestsContract>;
    deployContract(
      name: "TransferScalarTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferScalarTestsContract>;
    deployContract(
      name: "TransferTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferTestsContract>;
    deployContract(
      name: "TransferWithAllowance64_16TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_16TestsContract>;
    deployContract(
      name: "TransferWithAllowance64_32TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_32TestsContract>;
    deployContract(
      name: "TransferWithAllowance64_64TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_64TestsContract>;
    deployContract(
      name: "TransferWithAllowance64_8TestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowance64_8TestsContract>;
    deployContract(
      name: "TransferWithAllowanceScalarTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowanceScalarTestsContract>;
    deployContract(
      name: "TransferWithAllowanceTestsContract",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TransferWithAllowanceTestsContract>;
    deployContract(
      name: "PrivateERC20WalletMock",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC20WalletMock>;
    deployContract(
      name: "AccountOnboard",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AccountOnboard>;
    deployContract(
      name: "IPrivateERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IPrivateERC20>;
    deployContract(
      name: "PrivateERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC20>;
    deployContract(
      name: "PrivateERC721URIStorage",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC721URIStorage>;
    deployContract(
      name: "PrivateERC721",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.PrivateERC721>;
    deployContract(
      name: "MpcCore",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.MpcCore>;
    deployContract(
      name: "ExtendedOperations",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ExtendedOperations>;

    // default types
    getContractFactory(
      name: string,
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<ethers.ContractFactory>;
    getContractFactory(
      abi: any[],
      bytecode: ethers.BytesLike,
      signer?: ethers.Signer
    ): Promise<ethers.ContractFactory>;
    getContractAt(
      nameOrAbi: string | any[],
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
  }
}
