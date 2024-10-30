/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type { Signer, ContractDeployTransaction, ContractRunner } from "ethers";
import type { NonPayableOverrides } from "../../../../../common";
import type {
  PrivateERC721URIStorageMock,
  PrivateERC721URIStorageMockInterface,
} from "../../../../../contracts/mocks/token/PrivateERC721/PrivateERC721URIStorageMock";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
    ],
    name: "ERC721IncorrectOwner",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "operator",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "ERC721InsufficientApproval",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "approver",
        type: "address",
      },
    ],
    name: "ERC721InvalidApprover",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "operator",
        type: "address",
      },
    ],
    name: "ERC721InvalidOperator",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
    ],
    name: "ERC721InvalidOwner",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "receiver",
        type: "address",
      },
    ],
    name: "ERC721InvalidReceiver",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
    ],
    name: "ERC721InvalidSender",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "ERC721NonexistentToken",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "ERC721URIStorageNonMintedToken",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "approved",
        type: "address",
      },
      {
        indexed: true,
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "Approval",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "operator",
        type: "address",
      },
      {
        indexed: false,
        internalType: "bool",
        name: "approved",
        type: "bool",
      },
    ],
    name: "ApprovalForAll",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint256",
        name: "_fromTokenId",
        type: "uint256",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "_toTokenId",
        type: "uint256",
      },
    ],
    name: "BatchMetadataUpdate",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint256",
        name: "_tokenId",
        type: "uint256",
      },
    ],
    name: "MetadataUpdate",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        indexed: true,
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "Minted",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        indexed: true,
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "Transfer",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "approve",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
    ],
    name: "balanceOf",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "getApproved",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        internalType: "address",
        name: "operator",
        type: "address",
      },
    ],
    name: "isApprovedForAll",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        components: [
          {
            components: [
              {
                internalType: "ctUint64[]",
                name: "value",
                type: "uint256[]",
              },
            ],
            internalType: "struct ctString",
            name: "ciphertext",
            type: "tuple",
          },
          {
            internalType: "bytes[]",
            name: "signature",
            type: "bytes[]",
          },
        ],
        internalType: "struct itString",
        name: "itTokenURI",
        type: "tuple",
      },
    ],
    name: "mint",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "name",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "ownerOf",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "safeTransferFrom",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "safeTransferFrom",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "operator",
        type: "address",
      },
      {
        internalType: "bool",
        name: "approved",
        type: "bool",
      },
    ],
    name: "setApprovalForAll",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes4",
        name: "interfaceId",
        type: "bytes4",
      },
    ],
    name: "supportsInterface",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "symbol",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "tokenURI",
    outputs: [
      {
        components: [
          {
            internalType: "ctUint64[]",
            name: "value",
            type: "uint256[]",
          },
        ],
        internalType: "struct ctString",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "totalSupply",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "transferFrom",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60806040523480156200001157600080fd5b506040518060400160405280600781526020017f4578616d706c65000000000000000000000000000000000000000000000000008152506040518060400160405280600381526020017f45584c000000000000000000000000000000000000000000000000000000000081525081600090816200008f919062000324565b508060019081620000a1919062000324565b5050506200040b565b600081519050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806200012c57607f821691505b602082108103620001425762000141620000e4565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b600060088302620001ac7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff826200016d565b620001b886836200016d565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b600062000205620001ff620001f984620001d0565b620001da565b620001d0565b9050919050565b6000819050919050565b6200022183620001e4565b6200023962000230826200020c565b8484546200017a565b825550505050565b600090565b6200025062000241565b6200025d81848462000216565b505050565b5b8181101562000285576200027960008262000246565b60018101905062000263565b5050565b601f821115620002d4576200029e8162000148565b620002a9846200015d565b81016020851015620002b9578190505b620002d1620002c8856200015d565b83018262000262565b50505b505050565b600082821c905092915050565b6000620002f960001984600802620002d9565b1980831691505092915050565b6000620003148383620002e6565b9150826002028217905092915050565b6200032f82620000aa565b67ffffffffffffffff8111156200034b576200034a620000b5565b5b62000357825462000113565b6200036482828562000289565b600060209050601f8311600181146200039c576000841562000387578287015190505b62000393858262000306565b86555062000403565b601f198416620003ac8662000148565b60005b82811015620003d657848901518255600182019150602085019450602081019050620003af565b86831015620003f65784890151620003f2601f891682620002e6565b8355505b6001600288020188555050505b505050505050565b612ca6806200041b6000396000f3fe608060405234801561001057600080fd5b50600436106100f55760003560e01c80636352211e11610097578063a22cb46511610066578063a22cb46514610284578063b88d4fde146102a0578063c87b56dd146102bc578063e985e9c5146102ec576100f5565b80636352211e146101ea57806368862e1b1461021a57806370a082311461023657806395d89b4114610266576100f5565b8063095ea7b3116100d3578063095ea7b31461017857806318160ddd1461019457806323b872dd146101b257806342842e0e146101ce576100f5565b806301ffc9a7146100fa57806306fdde031461012a578063081812fc14610148575b600080fd5b610114600480360381019061010f9190611e3b565b61031c565b6040516101219190611e83565b60405180910390f35b610132610379565b60405161013f9190611f2e565b60405180910390f35b610162600480360381019061015d9190611f86565b61040b565b60405161016f9190611ff4565b60405180910390f35b610192600480360381019061018d919061203b565b610427565b005b61019c61043d565b6040516101a9919061208a565b60405180910390f35b6101cc60048036038101906101c791906120a5565b610447565b005b6101e860048036038101906101e391906120a5565b610549565b005b61020460048036038101906101ff9190611f86565b610569565b6040516102119190611ff4565b60405180910390f35b610234600480360381019061022f919061211c565b61057b565b005b610250600480360381019061024b9190612178565b6105fa565b60405161025d919061208a565b60405180910390f35b61026e6106b4565b60405161027b9190611f2e565b60405180910390f35b61029e600480360381019061029991906121d1565b610746565b005b6102ba60048036038101906102b59190612346565b61075c565b005b6102d660048036038101906102d19190611f86565b610779565b6040516102e391906124dd565b60405180910390f35b610306600480360381019061030191906124ff565b610801565b6040516103139190611e83565b60405180910390f35b60008060e01b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161480610372575061037182610895565b5b9050919050565b6060600080546103889061256e565b80601f01602080910402602001604051908101604052809291908181526020018280546103b49061256e565b80156104015780601f106103d657610100808354040283529160200191610401565b820191906000526020600020905b8154815290600101906020018083116103e457829003601f168201915b5050505050905090565b60006104168261090f565b5061042082610997565b9050919050565b61043982826104346109d4565b6109dc565b5050565b6000600754905090565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036104b95760006040517f64a0ae920000000000000000000000000000000000000000000000000000000081526004016104b09190611ff4565b60405180910390fd5b60006104cd83836104c86109d4565b6109ee565b90508373ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610543578382826040517f64283d7b00000000000000000000000000000000000000000000000000000000815260040161053a9392919061259f565b60405180910390fd5b50505050565b6105648383836040518060200160405280600081525061075c565b505050565b60006105748261090f565b9050919050565b6000600754905061058c8382610a9c565b610597338284610b95565b6001600760008282546105aa9190612605565b92505081905550808373ffffffffffffffffffffffffffffffffffffffff167f30385c845b448a36257a6a1716e6ad2e1bc2cbe333cde1e69fe849ad6511adfe60405160405180910390a3505050565b60008073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361066d5760006040517f89c62b640000000000000000000000000000000000000000000000000000000081526004016106649190611ff4565b60405180910390fd5b600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6060600180546106c39061256e565b80601f01602080910402602001604051908101604052809291908181526020018280546106ef9061256e565b801561073c5780601f106107115761010080835404028352916020019161073c565b820191906000526020600020905b81548152906001019060200180831161071f57829003601f168201915b5050505050905090565b6107586107516109d4565b8383610bbe565b5050565b610767848484610447565b61077384848484610d2d565b50505050565b610781611cff565b60066000838152602001908152602001600020600101604051806020016040529081600082018054806020026020016040519081016040528092919081815260200182805480156107f157602002820191906000526020600020905b8154815260200190600101908083116107dd575b5050505050815250509050919050565b6000600560008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16905092915050565b60007f80ac58cd000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161480610908575061090782610ee4565b5b9050919050565b60008061091b83610f4e565b9050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361098e57826040517f7e273289000000000000000000000000000000000000000000000000000000008152600401610985919061208a565b60405180910390fd5b80915050919050565b60006004600083815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b600033905090565b6109e98383836001610f8b565b505050565b600080610a726006600086815260200190815260200160002060000160405180602001604052908160008201805480602002602001604051908101604052809291908181526020018280548015610a6457602002820191906000526020600020905b815481526020019060010190808311610a50575b505050505081525050611150565b90506000610a8186868661122e565b9050610a908686846000611448565b80925050509392505050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610b0e5760006040517f64a0ae92000000000000000000000000000000000000000000000000000000008152600401610b059190611ff4565b60405180910390fd5b6000610b1c838360006109ee565b9050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610b905760006040517f73c6ac6e000000000000000000000000000000000000000000000000000000008152600401610b879190611ff4565b60405180910390fd5b505050565b6000610ba982610ba4906128f8565b611584565b9050610bb88484836001611448565b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610c2f57816040517f5b08ba18000000000000000000000000000000000000000000000000000000008152600401610c269190611ff4565b60405180910390fd5b80600560008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c3183604051610d209190611e83565b60405180910390a3505050565b60008373ffffffffffffffffffffffffffffffffffffffff163b1115610ede578273ffffffffffffffffffffffffffffffffffffffff1663150b7a02610d716109d4565b8685856040518563ffffffff1660e01b8152600401610d939493929190612960565b6020604051808303816000875af1925050508015610dcf57506040513d601f19601f82011682018060405250810190610dcc91906129c1565b60015b610e53573d8060008114610dff576040519150601f19603f3d011682016040523d82523d6000602084013e610e04565b606091505b506000815103610e4b57836040517f64a0ae92000000000000000000000000000000000000000000000000000000008152600401610e429190611ff4565b60405180910390fd5b805181602001fd5b63150b7a0260e01b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916817bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614610edc57836040517f64a0ae92000000000000000000000000000000000000000000000000000000008152600401610ed39190611ff4565b60405180910390fd5b505b50505050565b60007f01ffc9a7000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916149050919050565b60006002600083815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b8080610fc45750600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614155b156110f8576000610fd48461090f565b9050600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415801561103f57508273ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614155b801561105257506110508184610801565b155b1561109457826040517fa9fbf51f00000000000000000000000000000000000000000000000000000000815260040161108b9190611ff4565b60405180910390fd5b81156110f657838573ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560405160405180910390a45b505b836004600085815260200190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050505050565b611158611d12565b60008260000151519050600060405180602001604052808367ffffffffffffffff8111156111895761118861221b565b5b6040519080825280602002602001820160405280156111b75781602001602082028036833780820191505090505b50815250905060005b82811015611223576111ef856000015182815181106111e2576111e16129ee565b5b60200260200101516116eb565b82600001518281518110611206576112056129ee565b5b6020026020010181815250508061121c90612a1d565b90506111c0565b508092505050919050565b60008061123a84610f4e565b9050600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161461127c5761127b818486611788565b5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161461130d576112be600085600080610f8b565b6001600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b600073ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff1614611390576001600360008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055505b846002600086815260200190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550838573ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60405160405180910390a4809150509392505050565b600073ffffffffffffffffffffffffffffffffffffffff1661146984610569565b73ffffffffffffffffffffffffffffffffffffffff16036114c157826040517f868439130000000000000000000000000000000000000000000000000000000081526004016114b8919061208a565b60405180910390fd5b60006114cd838661184c565b90508115611541578060066000868152602001908152602001600020600082015181600001600082015181600001908051906020019061150e929190611d25565b5050506020820151816001016000820151816000019080519060200190611536929190611d25565b50505090505061157d565b8060200151600660008681526020019081526020016000206001016000820151816000019080519060200190611578929190611d25565b509050505b5050505050565b61158c611d12565b600082602001515190508083600001516000015151146115e1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016115d890612ab1565b60405180910390fd5b600060405180602001604052808367ffffffffffffffff8111156116085761160761221b565b5b6040519080825280602002602001820160405280156116365781602001602082028036833780820191505090505b508152509050611644611d72565b60005b838110156116df57856000015160000151818151811061166a576116696129ee565b5b602002602001015182600001818152505085602001518181518110611692576116916129ee565b5b602002602001015182602001819052506116ab8261187d565b836000015182815181106116c2576116c16129ee565b5b602002602001018181525050806116d890612a1d565b9050611647565b50819350505050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d2c135e560048081111561171d5761171c612ad1565b5b60f81b846040518363ffffffff1660e01b815260040161173e929190612b3b565b6020604051808303816000875af115801561175d573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906117819190612b79565b9050919050565b611793838383611924565b61184757600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361180857806040517f7e2732890000000000000000000000000000000000000000000000000000000081526004016117ff919061208a565b60405180910390fd5b81816040517f177e802f00000000000000000000000000000000000000000000000000000000815260040161183e929190612ba6565b60405180910390fd5b505050565b611854611d8c565b61185d836119e5565b816000018190525061186f8383611ac3565b816020018190525092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663e4f36e106004808111156118af576118ae612ad1565b5b60f81b846000015185602001516040518463ffffffff1660e01b81526004016118da93929190612bcf565b6020604051808303816000875af11580156118f9573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061191d9190612b79565b9050919050565b60008073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141580156119dc57508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16148061199d575061199c8484610801565b5b806119db57508273ffffffffffffffffffffffffffffffffffffffff166119c383610997565b73ffffffffffffffffffffffffffffffffffffffff16145b5b90509392505050565b6119ed611cff565b60008260000151519050600060405180602001604052808367ffffffffffffffff811115611a1e57611a1d61221b565b5b604051908082528060200260200182016040528015611a4c5781602001602082028036833780820191505090505b50815250905060005b82811015611ab857611a8485600001518281518110611a7757611a766129ee565b5b6020026020010151611ba3565b82600001518281518110611a9b57611a9a6129ee565b5b60200260200101818152505080611ab190612a1d565b9050611a55565b508092505050919050565b611acb611cff565b60008360000151519050600060405180602001604052808367ffffffffffffffff811115611afc57611afb61221b565b5b604051908082528060200260200182016040528015611b2a5781602001602082028036833780820191505090505b50815250905060005b82811015611b9757611b6386600001518281518110611b5557611b546129ee565b5b602002602001015186611c40565b82600001518281518110611b7a57611b796129ee565b5b60200260200101818152505080611b9090612a1d565b9050611b33565b50809250505092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663c50c9c02600480811115611bd557611bd4612ad1565b5b60f81b846040518363ffffffff1660e01b8152600401611bf6929190612b3b565b6020604051808303816000875af1158015611c15573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611c399190612b79565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e68600480811115611c7257611c71612ad1565b5b60f81b8585604051602001611c879190612c55565b6040516020818303038152906040526040518463ffffffff1660e01b8152600401611cb493929190612bcf565b6020604051808303816000875af1158015611cd3573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611cf79190612b79565b905092915050565b6040518060200160405280606081525090565b6040518060200160405280606081525090565b828054828255906000526020600020908101928215611d61579160200282015b82811115611d60578251825591602001919060010190611d45565b5b509050611d6e9190611db2565b5090565b604051806040016040528060008152602001606081525090565b6040518060400160405280611d9f611cff565b8152602001611dac611cff565b81525090565b5b80821115611dcb576000816000905550600101611db3565b5090565b6000604051905090565b600080fd5b600080fd5b60007fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b611e1881611de3565b8114611e2357600080fd5b50565b600081359050611e3581611e0f565b92915050565b600060208284031215611e5157611e50611dd9565b5b6000611e5f84828501611e26565b91505092915050565b60008115159050919050565b611e7d81611e68565b82525050565b6000602082019050611e986000830184611e74565b92915050565b600081519050919050565b600082825260208201905092915050565b60005b83811015611ed8578082015181840152602081019050611ebd565b60008484015250505050565b6000601f19601f8301169050919050565b6000611f0082611e9e565b611f0a8185611ea9565b9350611f1a818560208601611eba565b611f2381611ee4565b840191505092915050565b60006020820190508181036000830152611f488184611ef5565b905092915050565b6000819050919050565b611f6381611f50565b8114611f6e57600080fd5b50565b600081359050611f8081611f5a565b92915050565b600060208284031215611f9c57611f9b611dd9565b5b6000611faa84828501611f71565b91505092915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000611fde82611fb3565b9050919050565b611fee81611fd3565b82525050565b60006020820190506120096000830184611fe5565b92915050565b61201881611fd3565b811461202357600080fd5b50565b6000813590506120358161200f565b92915050565b6000806040838503121561205257612051611dd9565b5b600061206085828601612026565b925050602061207185828601611f71565b9150509250929050565b61208481611f50565b82525050565b600060208201905061209f600083018461207b565b92915050565b6000806000606084860312156120be576120bd611dd9565b5b60006120cc86828701612026565b93505060206120dd86828701612026565b92505060406120ee86828701611f71565b9150509250925092565b600080fd5b600060408284031215612113576121126120f8565b5b81905092915050565b6000806040838503121561213357612132611dd9565b5b600061214185828601612026565b925050602083013567ffffffffffffffff81111561216257612161611dde565b5b61216e858286016120fd565b9150509250929050565b60006020828403121561218e5761218d611dd9565b5b600061219c84828501612026565b91505092915050565b6121ae81611e68565b81146121b957600080fd5b50565b6000813590506121cb816121a5565b92915050565b600080604083850312156121e8576121e7611dd9565b5b60006121f685828601612026565b9250506020612207858286016121bc565b9150509250929050565b600080fd5b600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61225382611ee4565b810181811067ffffffffffffffff821117156122725761227161221b565b5b80604052505050565b6000612285611dcf565b9050612291828261224a565b919050565b600067ffffffffffffffff8211156122b1576122b061221b565b5b6122ba82611ee4565b9050602081019050919050565b82818337600083830152505050565b60006122e96122e484612296565b61227b565b90508281526020810184848401111561230557612304612216565b5b6123108482856122c7565b509392505050565b600082601f83011261232d5761232c612211565b5b813561233d8482602086016122d6565b91505092915050565b600080600080608085870312156123605761235f611dd9565b5b600061236e87828801612026565b945050602061237f87828801612026565b935050604061239087828801611f71565b925050606085013567ffffffffffffffff8111156123b1576123b0611dde565b5b6123bd87828801612318565b91505092959194509250565b600081519050919050565b600082825260208201905092915050565b6000819050602082019050919050565b6000819050919050565b600061241a61241561241084611f50565b6123f5565b611f50565b9050919050565b61242a816123ff565b82525050565b600061243c8383612421565b60208301905092915050565b6000602082019050919050565b6000612460826123c9565b61246a81856123d4565b9350612475836123e5565b8060005b838110156124a657815161248d8882612430565b975061249883612448565b925050600181019050612479565b5085935050505092915050565b600060208301600083015184820360008601526124d08282612455565b9150508091505092915050565b600060208201905081810360008301526124f781846124b3565b905092915050565b6000806040838503121561251657612515611dd9565b5b600061252485828601612026565b925050602061253585828601612026565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b6000600282049050600182168061258657607f821691505b6020821081036125995761259861253f565b5b50919050565b60006060820190506125b46000830186611fe5565b6125c1602083018561207b565b6125ce6040830184611fe5565b949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061261082611f50565b915061261b83611f50565b9250828201905080821115612633576126326125d6565b5b92915050565b600080fd5b600080fd5b600067ffffffffffffffff82111561265e5761265d61221b565b5b602082029050602081019050919050565b600080fd5b61267d81611f50565b811461268857600080fd5b50565b60008135905061269a81612674565b92915050565b60006126b36126ae84612643565b61227b565b905080838252602082019050602084028301858111156126d6576126d561266f565b5b835b818110156126ff57806126eb888261268b565b8452602084019350506020810190506126d8565b5050509392505050565b600082601f83011261271e5761271d612211565b5b813561272e8482602086016126a0565b91505092915050565b60006020828403121561274d5761274c612639565b5b612757602061227b565b9050600082013567ffffffffffffffff8111156127775761277661263e565b5b61278384828501612709565b60008301525092915050565b600067ffffffffffffffff8211156127aa576127a961221b565b5b602082029050602081019050919050565b60006127ce6127c98461278f565b61227b565b905080838252602082019050602084028301858111156127f1576127f061266f565b5b835b8181101561283857803567ffffffffffffffff81111561281657612815612211565b5b8086016128238982612318565b855260208501945050506020810190506127f3565b5050509392505050565b600082601f83011261285757612856612211565b5b81356128678482602086016127bb565b91505092915050565b60006040828403121561288657612885612639565b5b612890604061227b565b9050600082013567ffffffffffffffff8111156128b0576128af61263e565b5b6128bc84828501612737565b600083015250602082013567ffffffffffffffff8111156128e0576128df61263e565b5b6128ec84828501612842565b60208301525092915050565b60006129043683612870565b9050919050565b600081519050919050565b600082825260208201905092915050565b60006129328261290b565b61293c8185612916565b935061294c818560208601611eba565b61295581611ee4565b840191505092915050565b60006080820190506129756000830187611fe5565b6129826020830186611fe5565b61298f604083018561207b565b81810360608301526129a18184612927565b905095945050505050565b6000815190506129bb81611e0f565b92915050565b6000602082840312156129d7576129d6611dd9565b5b60006129e5848285016129ac565b91505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6000612a2882611f50565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203612a5a57612a596125d6565b5b600182019050919050565b7f4d50435f434f52453a20494e56414c49445f494e5055545f5445585400000000600082015250565b6000612a9b601c83611ea9565b9150612aa682612a65565b602082019050919050565b60006020820190508181036000830152612aca81612a8e565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b612b3581612b00565b82525050565b6000604082019050612b506000830185612b2c565b612b5d602083018461207b565b9392505050565b600081519050612b7381611f5a565b92915050565b600060208284031215612b8f57612b8e611dd9565b5b6000612b9d84828501612b64565b91505092915050565b6000604082019050612bbb6000830185611fe5565b612bc8602083018461207b565b9392505050565b6000606082019050612be46000830186612b2c565b612bf1602083018561207b565b8181036040830152612c038184612927565b9050949350505050565b60008160601b9050919050565b6000612c2582612c0d565b9050919050565b6000612c3782612c1a565b9050919050565b612c4f612c4a82611fd3565b612c2c565b82525050565b6000612c618284612c3e565b6014820191508190509291505056fea2646970667358221220a4b17b38841a46a489c5635a2699344a47b440e120cf8fb8098b35aaa098cbb764736f6c63430008140033";

type PrivateERC721URIStorageMockConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: PrivateERC721URIStorageMockConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class PrivateERC721URIStorageMock__factory extends ContractFactory {
  constructor(...args: PrivateERC721URIStorageMockConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(overrides || {});
  }
  override deploy(overrides?: NonPayableOverrides & { from?: string }) {
    return super.deploy(overrides || {}) as Promise<
      PrivateERC721URIStorageMock & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): PrivateERC721URIStorageMock__factory {
    return super.connect(runner) as PrivateERC721URIStorageMock__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): PrivateERC721URIStorageMockInterface {
    return new Interface(_abi) as PrivateERC721URIStorageMockInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): PrivateERC721URIStorageMock {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as PrivateERC721URIStorageMock;
  }
}
