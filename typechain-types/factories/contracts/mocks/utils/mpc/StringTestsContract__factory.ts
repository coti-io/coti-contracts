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
  StringTestsContract,
  StringTestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/StringTestsContract";

const _abi = [
  {
    inputs: [],
    name: "decryptNetworkEncryptedString",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getUserEncryptedString",
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
    name: "isEqual",
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
    name: "plaintext",
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
        name: "a_",
        type: "tuple",
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
        name: "b_",
        type: "tuple",
      },
      {
        internalType: "bool",
        name: "useEq",
        type: "bool",
      },
    ],
    name: "setIsEqual",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
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
        name: "it_",
        type: "tuple",
      },
    ],
    name: "setNetworkEncryptedString",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "str",
        type: "string",
      },
    ],
    name: "setPublicString",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
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
        name: "it_",
        type: "tuple",
      },
    ],
    name: "setUserEncryptedString",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b5061194c806100206000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c80638a4ef8541161005b5780638a4ef854146100e857806395bf7bb1146100f0578063acbe845214610103578063f9ce33a91461012057600080fd5b806314f6161f1461008d57806335435c00146100ab57806376ae56a5146100c057806378f7d733146100d5575b600080fd5b610095610133565b6040516100a291906110cb565b60405180910390f35b6100be6100b9366004611133565b6101a1565b005b6100c86101dc565b6040516100a291906111d4565b6100be6100e3366004611133565b61026a565b6100be61029a565b6100be6100fe3660046111e7565b61031a565b6003546101109060ff1681565b60405190151581526020016100a2565b6100be61012e366004611259565b610385565b6040805160208101909152606081526040805160008054602081810284018501855283018181529293919284929091849184018282801561019357602002820191906000526020600020905b81548152602001906001019080831161017f575b505050505081525050905090565b60006101b46101af836114cb565b610413565b90506101bf81610597565b805180516001916101d59183916020019061106b565b5050505050565b600280546101e9906115bb565b80601f0160208091040260200160405190810160405280929190818152602001828054610215906115bb565b80156102625780601f1061023757610100808354040283529160200191610262565b820191906000526020600020905b81548152906001019060200180831161024557829003601f168201915b505050505081565b60006102786101af836114cb565b90506102848133610667565b805180516000916101d59183916020019061106b565b6040805160018054602081810284018501855283018181526000946102fe9493928492918491908401828280156102f057602002820191906000526020600020905b8154815260200190600101908083116102dc575b50505050508152505061073b565b905061030981610803565b6002906103169082611653565b5050565b600061035b83838080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506108c592505050565b90506103678133610667565b8051805160009161037d9183916020019061106b565b505050505050565b60006103936101af856114cb565b905060006103a36101af856114cb565b9050600083156103be576103b78383610a4a565b90506103d3565b6103d06103cb8484610b13565b610bd4565b90505b6103dc81610c70565b600380547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0016911515919091179055505050505050565b604080516020810190915260608152602082015151825151518114610498576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601c60248201527f4d50435f434f52453a20494e56414c49445f494e5055545f5445585400000000604482015260640160405180910390fd5b600060405180602001604052808367ffffffffffffffff8111156104be576104be6112d6565b6040519080825280602002602001820160405280156104e7578160200160208202803683370190505b50905260408051808201909152600081526060602082015290915060005b8381101561058d578551518051829081106105225761052261176d565b60209081029190910181015183528601518051829081106105455761054561176d565b6020026020010151826020018190525061055e82610d01565b83518051839081106105725761057261176d565b6020908102919091010152610586816117cb565b9050610505565b5090949350505050565b6040805160208101909152606081528151516040805160208101909152600090808367ffffffffffffffff8111156105d1576105d16112d6565b6040519080825280602002602001820160405280156105fa578160200160208202803683370190505b509052905060005b8281101561065f57610630856000015182815181106106235761062361176d565b6020026020010151610d6a565b82518051839081106106445761064461176d565b6020908102919091010152610658816117cb565b9050610602565b509392505050565b6040805160208101909152606081528251516040805160208101909152600090808367ffffffffffffffff8111156106a1576106a16112d6565b6040519080825280602002602001820160405280156106ca578160200160208202803683370190505b509052905060005b8281101561073057610701866000015182815181106106f3576106f361176d565b602002602001015186610d7a565b82518051839081106107155761071561176d565b6020908102919091010152610729816117cb565b90506106d2565b509150505b92915050565b6040805160208101909152606081528151516040805160208101909152600090808367ffffffffffffffff811115610775576107756112d6565b60405190808252806020026020018201604052801561079e578160200160208202803683370190505b509052905060005b8281101561065f576107d4856000015182815181106107c7576107c761176d565b6020026020010151610e66565b82518051839081106107e8576107e861176d565b60209081029190910101526107fc816117cb565b90506107a6565b8051516060906000610816826008611803565b67ffffffffffffffff81111561082e5761082e6112d6565b6040519080825280601f01601f191660200182016040528015610858576020820181803683370190505b50905060008060005b848110156108ba5761088f876000015182815181106108825761088261176d565b6020026020010151610e76565b60c01b84830160200181905292506108a860088361181a565b91506108b3816117cb565b9050610861565b509195945050505050565b60408051602081019091526060815281518290600060086108e783600761181a565b6108f1919061185c565b9050600060405180602001604052808367ffffffffffffffff811115610919576109196112d6565b604051908082528060200260200182016040528015610942578160200160208202803683370190505b50905290506000805b610956846008611803565b811015610a3e57610968600882611870565b600003610978576000915061099b565b60088277ffffffffffffffffffffffffffffffffffffffffffffffff1916901b91505b848110156109e65760388682815181106109b7576109b761176d565b01602001517fff0000000000000000000000000000000000000000000000000000000000000016901c91909117905b6109f1600882611870565b600703610a2e57610a048260c01c610e86565b8351610a1160088461185c565b81518110610a2157610a2161176d565b6020026020010181815250505b610a37816117cb565b905061094b565b50909695505050505050565b815151815151600091908114610a6c57610a646000610ef6565b915050610735565b6000610ab48560000151600081518110610a8857610a8861176d565b60200260200101518560000151600081518110610aa757610aa761176d565b6020026020010151610f55565b905060015b8281101561073057610b0182610afc88600001518481518110610ade57610ade61176d565b602002602001015188600001518581518110610aa757610aa761176d565b610fd5565b9150610b0c816117cb565b9050610ab9565b815151815151600091908114610b2d57610a646001610ef6565b6000610b758560000151600081518110610b4957610b4961176d565b60200260200101518560000151600081518110610b6857610b6861176d565b6020026020010151610fe9565b905060015b8281101561073057610bc282610bbd88600001518481518110610b9f57610b9f61176d565b602002602001015188600001518581518110610b6857610b6861176d565b610ffe565b9150610bcd816117cb565b9050610b7a565b60006064631d79e49a825b60f81b846040518363ffffffff1660e01b8152600401610c2d9291907fff00000000000000000000000000000000000000000000000000000000000000929092168252602082015260400190565b6020604051808303816000875af1158015610c4c573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061073591906118b3565b6040517f0cfed56100000000000000000000000000000000000000000000000000000000815260006004820181905260248201839052908190606490630cfed561906044016020604051808303816000875af1158015610cd4573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610cf891906118b3565b15159392505050565b805160208201516040517fe4f36e1000000000000000000000000000000000000000000000000000000000815260009260649263e4f36e1092610c2d927f04000000000000000000000000000000000000000000000000000000000000009290916004016118cc565b6000606463c50c9c026004610bdf565b60408051606083901b7fffffffffffffffffffffffffffffffffffffffff0000000000000000000000001660208201528151601481830301815260348201928390527f3c6f0e6800000000000000000000000000000000000000000000000000000000909252600091606491633c6f0e6891610e1c917f04000000000000000000000000000000000000000000000000000000000000009188916038016118cc565b6020604051808303816000875af1158015610e3b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e5f91906118b3565b9392505050565b6000606463d2c135e56004610bdf565b60006064630cfed5616004610bdf565b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081527f0400000000000000000000000000000000000000000000000000000000000000600482015267ffffffffffffffff8216602482015260009060649063d9b60b6090604401610c2d565b60008082610f05576000610f08565b60015b6040517fd9b60b600000000000000000000000000000000000000000000000000000000081526000600482015260ff9190911660248201819052915060649063d9b60b6090604401610e1c565b60006064637c12a1eb610f6a6004808561100e565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b1681527fffffff000000000000000000000000000000000000000000000000000000000090911660048201526024810186905260448101859052606401610e1c565b6000606463fe9c73d1610f6a83808061100e565b600060646342094c56610f6a6004808561100e565b6000606463fb7da35f610f6a8380805b600081600281111561102257611022611884565b60ff16600884600481111561103957611039611884565b61ffff16901b61ffff16601086600481111561105757611057611884565b62ffffff16901b171760e81b949350505050565b8280548282559060005260206000209081019282156110a6579160200282015b828111156110a657825182559160200191906001019061108b565b506110b29291506110b6565b5090565b5b808211156110b257600081556001016110b7565b6020808252825182820182905280516040840181905260009291820190839060608601905b8083101561111057835182529284019260019290920191908401906110f0565b509695505050505050565b60006040828403121561112d57600080fd5b50919050565b60006020828403121561114557600080fd5b813567ffffffffffffffff81111561115c57600080fd5b6111688482850161111b565b949350505050565b6000815180845260005b818110156111965760208185018101518683018201520161117a565b5060006020828601015260207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f83011685010191505092915050565b602081526000610e5f6020830184611170565b600080602083850312156111fa57600080fd5b823567ffffffffffffffff8082111561121257600080fd5b818501915085601f83011261122657600080fd5b81358181111561123557600080fd5b86602082850101111561124757600080fd5b60209290920196919550909350505050565b60008060006060848603121561126e57600080fd5b833567ffffffffffffffff8082111561128657600080fd5b6112928783880161111b565b945060208601359150808211156112a857600080fd5b506112b58682870161111b565b925050604084013580151581146112cb57600080fd5b809150509250925092565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6040805190810167ffffffffffffffff81118282101715611328576113286112d6565b60405290565b6040516020810167ffffffffffffffff81118282101715611328576113286112d6565b604051601f82017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe016810167ffffffffffffffff81118282101715611398576113986112d6565b604052919050565b600067ffffffffffffffff8211156113ba576113ba6112d6565b5060051b60200190565b6000601f83818401126113d657600080fd5b823560206113eb6113e6836113a0565b611351565b82815260059290921b8501810191818101908784111561140a57600080fd5b8287015b848110156114bf57803567ffffffffffffffff8082111561142f5760008081fd5b818a0191508a603f8301126114445760008081fd5b8582013560408282111561145a5761145a6112d6565b611489887fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08c85011601611351565b92508183528c818386010111156114a05760008081fd5b818185018985013750600090820187015284525091830191830161140e565b50979650505050505050565b6000604082360312156114dd57600080fd5b6114e5611305565b823567ffffffffffffffff808211156114fd57600080fd5b8185019150602080833603121561151357600080fd5b61151b61132e565b83358381111561152a57600080fd5b939093019236601f85011261153e57600080fd5b833561154c6113e6826113a0565b81815260059190911b8501830190838101903683111561156b57600080fd5b958401955b8287101561158957863582529584019590840190611570565b835250508452858101359250818311156115a257600080fd5b6115ae368488016113c4565b9084015250909392505050565b600181811c908216806115cf57607f821691505b60208210810361112d577f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b601f82111561164e57600081815260208120601f850160051c8101602086101561162f5750805b601f850160051c820191505b8181101561037d5782815560010161163b565b505050565b815167ffffffffffffffff81111561166d5761166d6112d6565b6116818161167b84546115bb565b84611608565b602080601f8311600181146116d4576000841561169e5750858301515b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600386901b1c1916600185901b17855561037d565b6000858152602081207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08616915b8281101561172157888601518255948401946001909101908401611702565b508582101561175d57878501517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600388901b60f8161c191681555b5050505050600190811b01905550565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036117fc576117fc61179c565b5060010190565b80820281158282048414176107355761073561179c565b808201808211156107355761073561179c565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60008261186b5761186b61182d565b500490565b60008261187f5761187f61182d565b500690565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b6000602082840312156118c557600080fd5b5051919050565b7fff000000000000000000000000000000000000000000000000000000000000008416815282602082015260606040820152600061190d6060830184611170565b9594505050505056fea26469706673582212207e58f5ac9d7c9997ef0c931422961c39f2ee93069696c0549f0b13750d5061ac64736f6c63430008130033";

type StringTestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: StringTestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class StringTestsContract__factory extends ContractFactory {
  constructor(...args: StringTestsContractConstructorParams) {
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
      StringTestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): StringTestsContract__factory {
    return super.connect(runner) as StringTestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): StringTestsContractInterface {
    return new Interface(_abi) as StringTestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): StringTestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as StringTestsContract;
  }
}
