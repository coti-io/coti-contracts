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
import type { NonPayableOverrides } from "../../../../../../common";
import type {
  OffboardToUserKeyTestContract,
  OffboardToUserKeyTestContractInterface,
} from "../../../../../../contracts/mocks/utils/mpc/OffboardToUserKeyTestsContract.sol/OffboardToUserKeyTestContract";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "_from",
        type: "address",
      },
      {
        indexed: false,
        internalType: "bytes",
        name: "userKey",
        type: "bytes",
      },
    ],
    name: "AccountOnboarded",
    type: "event",
  },
  {
    inputs: [],
    name: "getCTs",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
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
    inputs: [],
    name: "getCt",
    outputs: [
      {
        internalType: "ctUint8",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getUserKey",
    outputs: [
      {
        internalType: "bytes",
        name: "",
        type: "bytes",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "signedEK",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "signature",
        type: "bytes",
      },
      {
        internalType: "address",
        name: "addr",
        type: "address",
      },
    ],
    name: "getUserKeyTest",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getX",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint8",
        name: "a",
        type: "uint8",
      },
      {
        internalType: "address",
        name: "addr",
        type: "address",
      },
    ],
    name: "offboardToUserTest",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "signedEK",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "signature",
        type: "bytes",
      },
    ],
    name: "userKeyTest",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b50611997806100206000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c80635197c7aa1161005b5780635197c7aa146100dd5780635cbfeea2146100fb578063fbe5fe1c14610119578063fbffef77146101495761007d565b80630844066e1461008257806320ee9bfb146100a05780633e99ee8c146100bc575b600080fd5b61008a61017c565b6040516100979190610ebb565b60405180910390f35b6100ba60048036038101906100b59190610f4f565b610186565b005b6100c46101eb565b6040516100d49493929190610fdf565b60405180910390f35b6100e561020b565b6040516100f29190611040565b60405180910390f35b610103610222565b60405161011091906110eb565b60405180910390f35b610133600480360381019061012e919061116b565b6102b4565b6040516101409190611040565b60405180910390f35b610163600480360381019061015e919061122c565b610359565b6040516101739493929190610fdf565b60405180910390f35b6000600254905090565b600061019485858585610415565b90503373ffffffffffffffffffffffffffffffffffffffff167fb67504ecfeef0230a06f661ea388c2947b4125a35e918ebff5889e3553c29c04826040516101dc91906110eb565b60405180910390a25050505050565b600080600080600354600454600554600654935093509350935090919293565b6000600160009054906101000a900460ff16905090565b6060600080546102319061129b565b80601f016020809104026020016040519081016040528092919081815260200182805461025d9061129b565b80156102aa5780601f1061027f576101008083540402835291602001916102aa565b820191906000526020600020905b81548152906001019060200180831161028d57829003601f168201915b5050505050905090565b6000806102c16005610614565b905060006102d08260056106b5565b90506102de88888888610415565b600090816102ec919061147b565b506102f7818561074f565b60028190555060006103088261080f565b90506000610315826108ad565b90506103208161094b565b600160006101000a81548160ff021916908360ff160217905550600160009054906101000a900460ff1694505050505095945050505050565b600080600080600061036a87610614565b9050600061037a8860ff166109e9565b9050600061038a8960ff16610a8b565b9050600061039a8a60ff16610b2f565b905060006103a8858b61074f565b905060006103b6858c610bd6565b905060006103c4858d610c96565b905060006103d2858e610d56565b9050836003819055508260048190555081600581905550806006819055506003546004546005546006549b509b509b509b50505050505050505092959194509250565b60606000858590508484905061042b919061157c565b67ffffffffffffffff811115610444576104436112cc565b5b6040519080825280601f01601f1916602001820160405280156104765781602001600182028036833780820191505090505b50905060005b848490508110156104f95784848281811061049a576104996115b0565b5b9050013560f81c60f81b8282815181106104b7576104b66115b0565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a90535080806104f1906115df565b91505061047c565b5060005b868690508110156105885786868281811061051b5761051a6115b0565b5b9050013560f81c60f81b828287879050610535919061157c565b81518110610546576105456115b0565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508080610580906115df565b9150506104fd565b50606473ffffffffffffffffffffffffffffffffffffffff1663a85f0ca2826040518263ffffffff1660e01b81526004016105c391906110eb565b600060405180830381865afa1580156105e0573d6000803e3d6000fd5b505050506040513d6000823e3d601f19601f820116820180604052508101906106099190611719565b915050949350505050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b606001600481111561064757610646611762565b5b60f81b8460ff166040518363ffffffff1660e01b815260040161066b9291906117cc565b6020604051808303816000875af115801561068a573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906106ae9190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16638c5d01506106e16001806002610e15565b858560ff166040518463ffffffff1660e01b815260040161070493929190611889565b6020604051808303816000875af1158015610723573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906107479190611821565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e686001600481111561078257610781611762565b5b60f81b85856040516020016107979190611908565b6040516020818303038152906040526040518463ffffffff1660e01b81526004016107c493929190611923565b6020604051808303816000875af11580156107e3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108079190611821565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663c50c9c026001600481111561084257610841611762565b5b60f81b846040518363ffffffff1660e01b81526004016108639291906117cc565b6020604051808303816000875af1158015610882573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906108a69190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d2c135e5600160048111156108e0576108df611762565b5b60f81b846040518363ffffffff1660e01b81526004016109019291906117cc565b6020604051808303816000875af1158015610920573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906109449190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16630cfed5616001600481111561097e5761097d611762565b5b60f81b846040518363ffffffff1660e01b815260040161099f9291906117cc565b6020604051808303816000875af11580156109be573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906109e29190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b6060026004811115610a1c57610a1b611762565b5b60f81b8461ffff166040518363ffffffff1660e01b8152600401610a419291906117cc565b6020604051808303816000875af1158015610a60573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a849190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b6060036004811115610abe57610abd611762565b5b60f81b8463ffffffff166040518363ffffffff1660e01b8152600401610ae59291906117cc565b6020604051808303816000875af1158015610b04573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b289190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b60600480811115610b6157610b60611762565b5b60f81b8467ffffffffffffffff166040518363ffffffff1660e01b8152600401610b8c9291906117cc565b6020604051808303816000875af1158015610bab573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610bcf9190611821565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e6860026004811115610c0957610c08611762565b5b60f81b8585604051602001610c1e9190611908565b6040516020818303038152906040526040518463ffffffff1660e01b8152600401610c4b93929190611923565b6020604051808303816000875af1158015610c6a573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610c8e9190611821565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e6860036004811115610cc957610cc8611762565b5b60f81b8585604051602001610cde9190611908565b6040516020818303038152906040526040518463ffffffff1660e01b8152600401610d0b93929190611923565b6020604051808303816000875af1158015610d2a573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d4e9190611821565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e68600480811115610d8857610d87611762565b5b60f81b8585604051602001610d9d9190611908565b6040516020818303038152906040526040518463ffffffff1660e01b8152600401610dca93929190611923565b6020604051808303816000875af1158015610de9573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e0d9190611821565b905092915050565b6000816002811115610e2a57610e29611762565b5b60ff166008846004811115610e4257610e41611762565b5b61ffff16901b61ffff166010866004811115610e6157610e60611762565b5b62ffffff16901b171760e81b90509392505050565b6000819050919050565b6000819050919050565b6000610ea5610ea0610e9b84610e76565b610e80565b610e76565b9050919050565b610eb581610e8a565b82525050565b6000602082019050610ed06000830184610eac565b92915050565b6000604051905090565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b60008083601f840112610f0f57610f0e610eea565b5b8235905067ffffffffffffffff811115610f2c57610f2b610eef565b5b602083019150836001820283011115610f4857610f47610ef4565b5b9250929050565b60008060008060408587031215610f6957610f68610ee0565b5b600085013567ffffffffffffffff811115610f8757610f86610ee5565b5b610f9387828801610ef9565b9450945050602085013567ffffffffffffffff811115610fb657610fb5610ee5565b5b610fc287828801610ef9565b925092505092959194509250565b610fd981610e76565b82525050565b6000608082019050610ff46000830187610fd0565b6110016020830186610fd0565b61100e6040830185610fd0565b61101b6060830184610fd0565b95945050505050565b600060ff82169050919050565b61103a81611024565b82525050565b60006020820190506110556000830184611031565b92915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561109557808201518184015260208101905061107a565b60008484015250505050565b6000601f19601f8301169050919050565b60006110bd8261105b565b6110c78185611066565b93506110d7818560208601611077565b6110e0816110a1565b840191505092915050565b6000602082019050818103600083015261110581846110b2565b905092915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006111388261110d565b9050919050565b6111488161112d565b811461115357600080fd5b50565b6000813590506111658161113f565b92915050565b60008060008060006060868803121561118757611186610ee0565b5b600086013567ffffffffffffffff8111156111a5576111a4610ee5565b5b6111b188828901610ef9565b9550955050602086013567ffffffffffffffff8111156111d4576111d3610ee5565b5b6111e088828901610ef9565b935093505060406111f388828901611156565b9150509295509295909350565b61120981611024565b811461121457600080fd5b50565b60008135905061122681611200565b92915050565b6000806040838503121561124357611242610ee0565b5b600061125185828601611217565b925050602061126285828601611156565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806112b357607f821691505b6020821081036112c6576112c561126c565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b60006008830261135d7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82611320565b6113678683611320565b95508019841693508086168417925050509392505050565b6000819050919050565b61139283610e8a565b6113a661139e8261137f565b84845461132d565b825550505050565b600090565b6113bb6113ae565b6113c6818484611389565b505050565b5b818110156113ea576113df6000826113b3565b6001810190506113cc565b5050565b601f82111561142f57611400816112fb565b61140984611310565b81016020851015611418578190505b61142c61142485611310565b8301826113cb565b50505b505050565b600082821c905092915050565b600061145260001984600802611434565b1980831691505092915050565b600061146b8383611441565b9150826002028217905092915050565b6114848261105b565b67ffffffffffffffff81111561149d5761149c6112cc565b5b6114a7825461129b565b6114b28282856113ee565b600060209050601f8311600181146114e557600084156114d3578287015190505b6114dd858261145f565b865550611545565b601f1984166114f3866112fb565b60005b8281101561151b578489015182556001820191506020850194506020810190506114f6565b868310156115385784890151611534601f891682611441565b8355505b6001600288020188555050505b505050505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061158782610e76565b915061159283610e76565b92508282019050808211156115aa576115a961154d565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60006115ea82610e76565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361161c5761161b61154d565b5b600182019050919050565b600080fd5b611635826110a1565b810181811067ffffffffffffffff82111715611654576116536112cc565b5b80604052505050565b6000611667610ed6565b9050611673828261162c565b919050565b600067ffffffffffffffff821115611693576116926112cc565b5b61169c826110a1565b9050602081019050919050565b60006116bc6116b784611678565b61165d565b9050828152602081018484840111156116d8576116d7611627565b5b6116e3848285611077565b509392505050565b600082601f830112611700576116ff610eea565b5b81516117108482602086016116a9565b91505092915050565b60006020828403121561172f5761172e610ee0565b5b600082015167ffffffffffffffff81111561174d5761174c610ee5565b5b611759848285016116eb565b91505092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b6117c681611791565b82525050565b60006040820190506117e160008301856117bd565b6117ee6020830184610fd0565b9392505050565b6117fe81610e76565b811461180957600080fd5b50565b60008151905061181b816117f5565b92915050565b60006020828403121561183757611836610ee0565b5b60006118458482850161180c565b91505092915050565b60007fffffff000000000000000000000000000000000000000000000000000000000082169050919050565b6118838161184e565b82525050565b600060608201905061189e600083018661187a565b6118ab6020830185610fd0565b6118b86040830184610fd0565b949350505050565b60008160601b9050919050565b60006118d8826118c0565b9050919050565b60006118ea826118cd565b9050919050565b6119026118fd8261112d565b6118df565b82525050565b600061191482846118f1565b60148201915081905092915050565b600060608201905061193860008301866117bd565b6119456020830185610fd0565b818103604083015261195781846110b2565b905094935050505056fea2646970667358221220def8896e279e289dd54f3e7964f10eb9283782f363550fce5a8690380762019864736f6c63430008140033";

type OffboardToUserKeyTestContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: OffboardToUserKeyTestContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class OffboardToUserKeyTestContract__factory extends ContractFactory {
  constructor(...args: OffboardToUserKeyTestContractConstructorParams) {
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
      OffboardToUserKeyTestContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): OffboardToUserKeyTestContract__factory {
    return super.connect(runner) as OffboardToUserKeyTestContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): OffboardToUserKeyTestContractInterface {
    return new Interface(_abi) as OffboardToUserKeyTestContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): OffboardToUserKeyTestContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as OffboardToUserKeyTestContract;
  }
}
