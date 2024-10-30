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
  Miscellaneous1TestsContract,
  Miscellaneous1TestsContractInterface,
} from "../../../../../contracts/mocks/utils/mpc/Miscellaneous1TestsContract";

const _abi = [
  {
    inputs: [
      {
        internalType: "bool",
        name: "a",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "b",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "bit",
        type: "bool",
      },
    ],
    name: "booleanTest",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint64[10]",
        name: "randoms",
        type: "uint64[10]",
      },
      {
        internalType: "uint256",
        name: "size",
        type: "uint256",
      },
      {
        internalType: "uint8",
        name: "numBits",
        type: "uint8",
      },
    ],
    name: "checkBound",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getBooleanResults",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
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
    name: "getRandom",
    outputs: [
      {
        internalType: "uint64",
        name: "",
        type: "uint64",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bool",
        name: "isBounded",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "numBits",
        type: "uint8",
      },
    ],
    name: "randTest_",
    outputs: [
      {
        internalType: "uint64",
        name: "",
        type: "uint64",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint8",
        name: "numBits",
        type: "uint8",
      },
    ],
    name: "randomBoundedTest",
    outputs: [
      {
        internalType: "uint64",
        name: "",
        type: "uint64",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "randomTest",
    outputs: [
      {
        internalType: "uint64",
        name: "",
        type: "uint64",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405260008060006101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555034801561003957600080fd5b50611fc5806100496000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063926605781161005b57806392660578146100f5578063aacc5a1714610111578063dbc221d01461012f578063dfbba08f1461014b5761007d565b8063103bdb8714610082578063598f9579146100a75780635adb5778146100d7575b600080fd5b61008a61017b565b60405161009e9897969594939291906117d7565b60405180910390f35b6100c160048036038101906100bc919061189d565b610221565b6040516100ce91906118ed565b60405180910390f35b6100df610235565b6040516100ec91906118ed565b60405180910390f35b61010f600480360381019061010a9190611934565b610247565b005b6101196103db565b60405161012691906118ed565b60405180910390f35b61014960048036038101906101449190611b30565b6103f8565b005b61016560048036038101906101609190611b86565b610486565b60405161017291906118ed565b60405180910390f35b600080600080600080600080600060089054906101000a900460ff16600060099054906101000a900460ff166000600a9054906101000a900460ff166000600b9054906101000a900460ff166000600c9054906101000a900460ff166000600d9054906101000a900460ff166000600e9054906101000a900460ff166000600f9054906101000a900460ff16975097509750975097509750975097509091929394959697565b600061022e600183610486565b9050919050565b6000610242600080610486565b905090565b600061025284610858565b9050600061025f84610858565b9050600061026c84610858565b905061028061027b848461090c565b6109a3565b600060086101000a81548160ff0219169083151502179055506102ab6102a68484610a4a565b6109a3565b600060096101000a81548160ff0219169083151502179055506102d66102d18484610ae1565b6109a3565b6000600a6101000a81548160ff0219169083151502179055506103006102fb84610b78565b6109a3565b6000600b6101000a81548160ff02191690831515021790555061032b6103268484610c16565b6109a3565b6000600c6101000a81548160ff0219169083151502179055506103566103518484610cad565b6109a3565b6000600d6101000a81548160ff02191690831515021790555061038261037d828585610d44565b6109a3565b6000600e6101000a81548160ff02191690831515021790555060006103a684610dde565b90506103b96103b482610e7c565b6109a3565b6000600f6101000a81548160ff02191690831515021790555050505050505050565b60008060009054906101000a900467ffffffffffffffff16905090565b60005b82811015610480578160ff166001901b8482600a811061041e5761041d611bc6565b5b602002015167ffffffffffffffff161061046d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161046490611c78565b60405180910390fd5b808061047890611cc7565b9150506103fb565b50505050565b600080600a9050610495611799565b60005b8281101561054957856104ef576104b56104b0610f1a565b610fb4565b60ff168282600a81106104cb576104ca611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff1681525050610536565b6105006104fb86611052565b610fb4565b60ff168282600a811061051657610515611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff16815250505b808061054190611cc7565b915050610498565b50806000600a811061055e5761055d611bc6565b5b60200201516000806101000a81548167ffffffffffffffff021916908367ffffffffffffffff160217905550841561059c5761059b8183866103f8565b5b6105a681836110f0565b846105b057600391505b60005b82811015610666578561060b576105d06105cb6111b9565b611253565b61ffff168282600a81106105e7576105e6611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff1681525050610653565b61061c610617866112f1565b611253565b61ffff168282600a811061063357610632611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff16815250505b808061065e90611cc7565b9150506105b3565b508415610679576106788183866103f8565b5b61068381836110f0565b8461068d57600391505b60005b8281101561074757856106ea576106ad6106a861138f565b611429565b63ffffffff168282600a81106106c6576106c5611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff1681525050610734565b6106fb6106f6866114c7565b611429565b63ffffffff168282600a811061071457610713611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff16815250505b808061073f90611cc7565b915050610690565b50841561075a576107598183866103f8565b5b61076481836110f0565b8461076e57600291505b60005b8281101561081c57856107c55761078e610789611565565b6115fe565b8282600a81106107a1576107a0611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff1681525050610809565b6107d66107d18661169b565b6115fe565b8282600a81106107e9576107e8611bc6565b5b602002019067ffffffffffffffff16908167ffffffffffffffff16815250505b808061081490611cc7565b915050610771565b50841561082f5761082e8183866103f8565b5b61083981836110f0565b60008054906101000a900467ffffffffffffffff169250505092915050565b6000808261086757600061086a565b60015b60ff169050606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b60600060048111156108a05761089f611d0f565b5b60f81b836040518363ffffffff1660e01b81526004016108c1929190611d88565b6020604051808303816000875af11580156108e0573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906109049190611dc6565b915050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663fe9c73d16109386000806000611738565b85856040518463ffffffff1660e01b815260040161095893929190611e2e565b6020604051808303816000875af1158015610977573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061099b9190611dc6565b905092915050565b600080606473ffffffffffffffffffffffffffffffffffffffff16630cfed561600060048111156109d7576109d6611d0f565b5b60f81b856040518363ffffffff1660e01b81526004016109f8929190611d88565b6020604051808303816000875af1158015610a17573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a3b9190611dc6565b90506000811415915050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663fb7da35f610a766000806000611738565b85856040518463ffffffff1660e01b8152600401610a9693929190611e2e565b6020604051808303816000875af1158015610ab5573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610ad99190611dc6565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16636f962e2c610b0d6000806000611738565b85856040518463ffffffff1660e01b8152600401610b2d93929190611e2e565b6020604051808303816000875af1158015610b4c573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b709190611dc6565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16631d79e49a60006004811115610bab57610baa611d0f565b5b60f81b846040518363ffffffff1660e01b8152600401610bcc929190611d88565b6020604051808303816000875af1158015610beb573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610c0f9190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16637c12a1eb610c426000806000611738565b85856040518463ffffffff1660e01b8152600401610c6293929190611e2e565b6020604051808303816000875af1158015610c81573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610ca59190611dc6565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff166342094c56610cd96000806000611738565b85856040518463ffffffff1660e01b8152600401610cf993929190611e2e565b6020604051808303816000875af1158015610d18573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d3c9190611dc6565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff166320cc408d610d706000806000611738565b8686866040518563ffffffff1660e01b8152600401610d929493929190611e65565b6020604051808303816000875af1158015610db1573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610dd59190611dc6565b90509392505050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663c50c9c0260006004811115610e1157610e10611d0f565b5b60f81b846040518363ffffffff1660e01b8152600401610e32929190611d88565b6020604051808303816000875af1158015610e51573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e759190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d2c135e560006004811115610eaf57610eae611d0f565b5b60f81b846040518363ffffffff1660e01b8152600401610ed0929190611d88565b6020604051808303816000875af1158015610eef573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610f139190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663134eb89060016004811115610f4d57610f4c611d0f565b5b60f81b6040518263ffffffff1660e01b8152600401610f6c9190611eaa565b6020604051808303816000875af1158015610f8b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610faf9190611dc6565b905090565b6000606473ffffffffffffffffffffffffffffffffffffffff16630cfed56160016004811115610fe757610fe6611d0f565b5b60f81b846040518363ffffffff1660e01b8152600401611008929190611d88565b6020604051808303816000875af1158015611027573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061104b9190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663072d17fc6001600481111561108557611084611d0f565b5b60f81b846040518363ffffffff1660e01b81526004016110a6929190611ed4565b6020604051808303816000875af11580156110c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906110e99190611dc6565b9050919050565b6000600190506000600190505b82811015611171578381600a811061111857611117611bc6565b5b602002015167ffffffffffffffff16846000600a811061113b5761113a611bc6565b5b602002015167ffffffffffffffff160361115e57818061115a90611cc7565b9250505b808061116990611cc7565b9150506110fd565b508181036111b4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016111ab90611f6f565b60405180910390fd5b505050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663134eb890600260048111156111ec576111eb611d0f565b5b60f81b6040518263ffffffff1660e01b815260040161120b9190611eaa565b6020604051808303816000875af115801561122a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061124e9190611dc6565b905090565b6000606473ffffffffffffffffffffffffffffffffffffffff16630cfed5616002600481111561128657611285611d0f565b5b60f81b846040518363ffffffff1660e01b81526004016112a7929190611d88565b6020604051808303816000875af11580156112c6573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112ea9190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663072d17fc6002600481111561132457611323611d0f565b5b60f81b846040518363ffffffff1660e01b8152600401611345929190611ed4565b6020604051808303816000875af1158015611364573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906113889190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663134eb890600360048111156113c2576113c1611d0f565b5b60f81b6040518263ffffffff1660e01b81526004016113e19190611eaa565b6020604051808303816000875af1158015611400573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114249190611dc6565b905090565b6000606473ffffffffffffffffffffffffffffffffffffffff16630cfed5616003600481111561145c5761145b611d0f565b5b60f81b846040518363ffffffff1660e01b815260040161147d929190611d88565b6020604051808303816000875af115801561149c573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114c09190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663072d17fc600360048111156114fa576114f9611d0f565b5b60f81b846040518363ffffffff1660e01b815260040161151b929190611ed4565b6020604051808303816000875af115801561153a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061155e9190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663134eb89060048081111561159757611596611d0f565b5b60f81b6040518263ffffffff1660e01b81526004016115b69190611eaa565b6020604051808303816000875af11580156115d5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906115f99190611dc6565b905090565b6000606473ffffffffffffffffffffffffffffffffffffffff16630cfed5616004808111156116305761162f611d0f565b5b60f81b846040518363ffffffff1660e01b8152600401611651929190611d88565b6020604051808303816000875af1158015611670573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906116949190611dc6565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663072d17fc6004808111156116cd576116cc611d0f565b5b60f81b846040518363ffffffff1660e01b81526004016116ee929190611ed4565b6020604051808303816000875af115801561170d573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906117319190611dc6565b9050919050565b600081600281111561174d5761174c611d0f565b5b60ff16600884600481111561176557611764611d0f565b5b61ffff16901b61ffff16601086600481111561178457611783611d0f565b5b62ffffff16901b171760e81b90509392505050565b604051806101400160405280600a90602082028036833780820191505090505090565b60008115159050919050565b6117d1816117bc565b82525050565b6000610100820190506117ed600083018b6117c8565b6117fa602083018a6117c8565b61180760408301896117c8565b61181460608301886117c8565b61182160808301876117c8565b61182e60a08301866117c8565b61183b60c08301856117c8565b61184860e08301846117c8565b9998505050505050505050565b6000604051905090565b600080fd5b600060ff82169050919050565b61187a81611864565b811461188557600080fd5b50565b60008135905061189781611871565b92915050565b6000602082840312156118b3576118b261185f565b5b60006118c184828501611888565b91505092915050565b600067ffffffffffffffff82169050919050565b6118e7816118ca565b82525050565b600060208201905061190260008301846118de565b92915050565b611911816117bc565b811461191c57600080fd5b50565b60008135905061192e81611908565b92915050565b60008060006060848603121561194d5761194c61185f565b5b600061195b8682870161191f565b935050602061196c8682870161191f565b925050604061197d8682870161191f565b9150509250925092565b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6119d58261198c565b810181811067ffffffffffffffff821117156119f4576119f361199d565b5b80604052505050565b6000611a07611855565b9050611a1382826119cc565b919050565b600067ffffffffffffffff821115611a3357611a3261199d565b5b602082029050919050565b600080fd5b611a4c816118ca565b8114611a5757600080fd5b50565b600081359050611a6981611a43565b92915050565b6000611a82611a7d84611a18565b6119fd565b90508060208402830185811115611a9c57611a9b611a3e565b5b835b81811015611ac55780611ab18882611a5a565b845260208401935050602081019050611a9e565b5050509392505050565b600082601f830112611ae457611ae3611987565b5b600a611af1848285611a6f565b91505092915050565b6000819050919050565b611b0d81611afa565b8114611b1857600080fd5b50565b600081359050611b2a81611b04565b92915050565b60008060006101808486031215611b4a57611b4961185f565b5b6000611b5886828701611acf565b935050610140611b6a86828701611b1b565b925050610160611b7c86828701611888565b9150509250925092565b60008060408385031215611b9d57611b9c61185f565b5b6000611bab8582860161191f565b9250506020611bbc85828601611888565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082825260208201905092915050565b7f72616e646f6d546573743a2072616e646f6d206661696c65642c206f7574206f60008201527f6620626f756e6473000000000000000000000000000000000000000000000000602082015250565b6000611c62602883611bf5565b9150611c6d82611c06565b604082019050919050565b60006020820190508181036000830152611c9181611c55565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000611cd282611afa565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611d0457611d03611c98565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b611d7381611d3e565b82525050565b611d8281611afa565b82525050565b6000604082019050611d9d6000830185611d6a565b611daa6020830184611d79565b9392505050565b600081519050611dc081611b04565b92915050565b600060208284031215611ddc57611ddb61185f565b5b6000611dea84828501611db1565b91505092915050565b60007fffffff000000000000000000000000000000000000000000000000000000000082169050919050565b611e2881611df3565b82525050565b6000606082019050611e436000830186611e1f565b611e506020830185611d79565b611e5d6040830184611d79565b949350505050565b6000608082019050611e7a6000830187611e1f565b611e876020830186611d79565b611e946040830185611d79565b611ea16060830184611d79565b95945050505050565b6000602082019050611ebf6000830184611d6a565b92915050565b611ece81611864565b82525050565b6000604082019050611ee96000830185611d6a565b611ef66020830184611ec5565b9392505050565b7f72616e646f6d546573743a2072616e646f6d206661696c65642c20616c6c207660008201527f616c75657320617265207468652073616d650000000000000000000000000000602082015250565b6000611f59603283611bf5565b9150611f6482611efd565b604082019050919050565b60006020820190508181036000830152611f8881611f4c565b905091905056fea2646970667358221220f20996b8e6f5adfd164a85027d33fe534d931940f9c4a8e8896c3eb452bc4cbd64736f6c63430008140033";

type Miscellaneous1TestsContractConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: Miscellaneous1TestsContractConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class Miscellaneous1TestsContract__factory extends ContractFactory {
  constructor(...args: Miscellaneous1TestsContractConstructorParams) {
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
      Miscellaneous1TestsContract & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(
    runner: ContractRunner | null
  ): Miscellaneous1TestsContract__factory {
    return super.connect(runner) as Miscellaneous1TestsContract__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): Miscellaneous1TestsContractInterface {
    return new Interface(_abi) as Miscellaneous1TestsContractInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): Miscellaneous1TestsContract {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as Miscellaneous1TestsContract;
  }
}