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
  "0x608060405234801561001057600080fd5b506125fe806100206000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c80638a4ef8541161005b5780638a4ef8541461010157806395bf7bb11461010b578063acbe845214610127578063f9ce33a91461014557610088565b806314f6161f1461008d57806335435c00146100ab57806376ae56a5146100c757806378f7d733146100e5575b600080fd5b610095610161565b6040516100a29190611777565b60405180910390f35b6100c560048036038101906100c091906117d1565b6101d3565b005b6100cf610218565b6040516100dc91906118aa565b60405180910390f35b6100ff60048036038101906100fa91906117d1565b6102a6565b005b6101096102eb565b005b61012560048036038101906101209190611931565b610377565b005b61012f6103f8565b60405161013c9190611999565b60405180910390f35b61015f600480360381019061015a91906119e0565b61040b565b005b6101696115af565b6000604051806020016040529081600082018054806020026020016040519081016040528092919081815260200182805480156101c557602002820191906000526020600020905b8154815260200190600101908083116101b1575b505050505081525050905090565b60006101e7826101e290611e55565b61048f565b90506101f2816105f6565b600160008201518160000190805190602001906102109291906115c2565b509050505050565b6002805461022590611e97565b80601f016020809104026020016040519081016040528092919081815260200182805461025190611e97565b801561029e5780601f106102735761010080835404028352916020019161029e565b820191906000526020600020905b81548152906001019060200180831161028157829003601f168201915b505050505081565b60006102ba826102b590611e55565b61048f565b90506102c681336106d4565b6000808201518160000190805190602001906102e39291906115c2565b509050505050565b600061035a60016040518060200160405290816000820180548060200260200160405190810160405280929190818152602001828054801561034c57602002820191906000526020600020905b815481526020019060010190808311610338575b5050505050815250506107b4565b905061036581610892565b600290816103739190612048565b5050565b60006103c683838080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505061096a565b90506103d281336106d4565b6000808201518160000190805190602001906103ef9291906115c2565b50905050505050565b600360009054906101000a900460ff1681565b600061041f8461041a90611e55565b61048f565b905060006104358461043090611e55565b61048f565b905060008315610450576104498383610b2f565b9050610465565b61046261045d8484610c22565b610d15565b90505b61046e81610db3565b600360006101000a81548160ff021916908315150217905550505050505050565b61049761160f565b600082602001515190508083600001516000015151146104ec576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104e390612166565b60405180910390fd5b600060405180602001604052808367ffffffffffffffff81111561051357610512611a70565b5b6040519080825280602002602001820160405280156105415781602001602082028036833780820191505090505b50815250905061054f611622565b60005b838110156105ea57856000015160000151818151811061057557610574612186565b5b60200260200101518260000181815250508560200151818151811061059d5761059c612186565b5b602002602001015182602001819052506105b682610e5a565b836000015182815181106105cd576105cc612186565b5b602002602001018181525050806105e3906121e4565b9050610552565b50819350505050919050565b6105fe6115af565b60008260000151519050600060405180602001604052808367ffffffffffffffff81111561062f5761062e611a70565b5b60405190808252806020026020018201604052801561065d5781602001602082028036833780820191505090505b50815250905060005b828110156106c9576106958560000151828151811061068857610687612186565b5b6020026020010151610f01565b826000015182815181106106ac576106ab612186565b5b602002602001018181525050806106c2906121e4565b9050610666565b508092505050919050565b6106dc6115af565b60008360000151519050600060405180602001604052808367ffffffffffffffff81111561070d5761070c611a70565b5b60405190808252806020026020018201604052801561073b5781602001602082028036833780820191505090505b50815250905060005b828110156107a8576107748660000151828151811061076657610765612186565b5b602002602001015186610f9e565b8260000151828151811061078b5761078a612186565b5b602002602001018181525050806107a1906121e4565b9050610744565b50809250505092915050565b6107bc61160f565b60008260000151519050600060405180602001604052808367ffffffffffffffff8111156107ed576107ec611a70565b5b60405190808252806020026020018201604052801561081b5781602001602082028036833780820191505090505b50815250905060005b82811015610887576108538560000151828151811061084657610845612186565b5b602002602001015161105d565b8260000151828151811061086a57610869612186565b5b60200260200101818152505080610880906121e4565b9050610824565b508092505050919050565b60606000826000015151905060006008826108ad919061222c565b67ffffffffffffffff8111156108c6576108c5611a70565b5b6040519080825280601f01601f1916602001820160405280156108f85781602001600182028036833780820191505090505b50905060008060005b8481101561095d576109308760000151828151811061092357610922612186565b5b60200260200101516110fa565b60c01b9250828260200185015260088261094a919061226e565b915080610956906121e4565b9050610901565b5082945050505050919050565b61097261160f565b60008290506000815190506000600860078361098e919061226e565b61099891906122d1565b9050600060405180602001604052808367ffffffffffffffff8111156109c1576109c0611a70565b5b6040519080825280602002602001820160405280156109ef5781602001602082028036833780820191505090505b508152509050600080600090505b600884610a0a919061222c565b811015610b21576000600882610a209190612302565b03610a3157600060c01b9150610a54565b60088277ffffffffffffffffffffffffffffffffffffffffffffffff1916901b91505b84811015610ac0576038868281518110610a7157610a70612186565b5b602001015160f81c60f81b7effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191677ffffffffffffffffffffffffffffffffffffffffffffffff1916901c821791505b6007600882610acf9190612302565b03610b1057610ae08260c01c611197565b8360000151600883610af291906122d1565b81518110610b0357610b02612186565b5b6020026020010181815250505b80610b1a906121e4565b90506109fd565b508195505050505050919050565b60008083600001515190508260000151518114610b5857610b50600061123e565b915050610c1c565b6000610ba28560000151600081518110610b7557610b74612186565b5b60200260200101518560000151600081518110610b9557610b94612186565b5b60200260200101516112f2565b90506000600190505b82811015610c1557610c0282610bfd88600001518481518110610bd157610bd0612186565b5b602002602001015188600001518581518110610bf057610bef612186565b5b60200260200101516112f2565b611389565b915080610c0e906121e4565b9050610bab565b5080925050505b92915050565b60008083600001515190508260000151518114610c4b57610c43600161123e565b915050610d0f565b6000610c958560000151600081518110610c6857610c67612186565b5b60200260200101518560000151600081518110610c8857610c87612186565b5b6020026020010151611420565b90506000600190505b82811015610d0857610cf582610cf088600001518481518110610cc457610cc3612186565b5b602002602001015188600001518581518110610ce357610ce2612186565b5b6020026020010151611420565b6114b7565b915080610d01906121e4565b9050610c9e565b5080925050505b92915050565b6000606473ffffffffffffffffffffffffffffffffffffffff16631d79e49a60006004811115610d4857610d47612333565b5b60f81b846040518363ffffffff1660e01b8152600401610d699291906123ac565b6020604051808303816000875af1158015610d88573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610dac9190612401565b9050919050565b600080606473ffffffffffffffffffffffffffffffffffffffff16630cfed56160006004811115610de757610de6612333565b5b60f81b856040518363ffffffff1660e01b8152600401610e089291906123ac565b6020604051808303816000875af1158015610e27573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610e4b9190612401565b90506000811415915050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663e4f36e10600480811115610e8c57610e8b612333565b5b60f81b846000015185602001516040518463ffffffff1660e01b8152600401610eb793929190612483565b6020604051808303816000875af1158015610ed6573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610efa9190612401565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663c50c9c02600480811115610f3357610f32612333565b5b60f81b846040518363ffffffff1660e01b8152600401610f549291906123ac565b6020604051808303816000875af1158015610f73573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610f979190612401565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16633c6f0e68600480811115610fd057610fcf612333565b5b60f81b8585604051602001610fe5919061253b565b6040516020818303038152906040526040518463ffffffff1660e01b815260040161101293929190612483565b6020604051808303816000875af1158015611031573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906110559190612401565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d2c135e560048081111561108f5761108e612333565b5b60f81b846040518363ffffffff1660e01b81526004016110b09291906123ac565b6020604051808303816000875af11580156110cf573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906110f39190612401565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16630cfed56160048081111561112c5761112b612333565b5b60f81b846040518363ffffffff1660e01b815260040161114d9291906123ac565b6020604051808303816000875af115801561116c573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906111909190612401565b9050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b606004808111156111c9576111c8612333565b5b60f81b8467ffffffffffffffff166040518363ffffffff1660e01b81526004016111f49291906123ac565b6020604051808303816000875af1158015611213573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112379190612401565b9050919050565b6000808261124d576000611250565b60015b60ff169050606473ffffffffffffffffffffffffffffffffffffffff1663d9b60b606000600481111561128657611285612333565b5b60f81b836040518363ffffffff1660e01b81526004016112a79291906123ac565b6020604051808303816000875af11580156112c6573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112ea9190612401565b915050919050565b6000606473ffffffffffffffffffffffffffffffffffffffff16637c12a1eb61131e600480600061154e565b85856040518463ffffffff1660e01b815260040161133e93929190612591565b6020604051808303816000875af115801561135d573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906113819190612401565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663fe9c73d16113b5600080600061154e565b85856040518463ffffffff1660e01b81526004016113d593929190612591565b6020604051808303816000875af11580156113f4573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114189190612401565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff166342094c5661144c600480600061154e565b85856040518463ffffffff1660e01b815260040161146c93929190612591565b6020604051808303816000875af115801561148b573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114af9190612401565b905092915050565b6000606473ffffffffffffffffffffffffffffffffffffffff1663fb7da35f6114e3600080600061154e565b85856040518463ffffffff1660e01b815260040161150393929190612591565b6020604051808303816000875af1158015611522573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906115469190612401565b905092915050565b600081600281111561156357611562612333565b5b60ff16600884600481111561157b5761157a612333565b5b61ffff16901b61ffff16601086600481111561159a57611599612333565b5b62ffffff16901b171760e81b90509392505050565b6040518060200160405280606081525090565b8280548282559060005260206000209081019282156115fe579160200282015b828111156115fd5782518255916020019190600101906115e2565b5b50905061160b919061163c565b5090565b6040518060200160405280606081525090565b604051806040016040528060008152602001606081525090565b5b8082111561165557600081600090555060010161163d565b5090565b600081519050919050565b600082825260208201905092915050565b6000819050602082019050919050565b6000819050919050565b6000819050919050565b60006116b46116af6116aa84611685565b61168f565b611685565b9050919050565b6116c481611699565b82525050565b60006116d683836116bb565b60208301905092915050565b6000602082019050919050565b60006116fa82611659565b6117048185611664565b935061170f83611675565b8060005b8381101561174057815161172788826116ca565b9750611732836116e2565b925050600181019050611713565b5085935050505092915050565b6000602083016000830151848203600086015261176a82826116ef565b9150508091505092915050565b60006020820190508181036000830152611791818461174d565b905092915050565b6000604051905090565b600080fd5b600080fd5b600080fd5b6000604082840312156117c8576117c76117ad565b5b81905092915050565b6000602082840312156117e7576117e66117a3565b5b600082013567ffffffffffffffff811115611805576118046117a8565b5b611811848285016117b2565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b83811015611854578082015181840152602081019050611839565b60008484015250505050565b6000601f19601f8301169050919050565b600061187c8261181a565b6118868185611825565b9350611896818560208601611836565b61189f81611860565b840191505092915050565b600060208201905081810360008301526118c48184611871565b905092915050565b600080fd5b600080fd5b600080fd5b60008083601f8401126118f1576118f06118cc565b5b8235905067ffffffffffffffff81111561190e5761190d6118d1565b5b60208301915083600182028301111561192a576119296118d6565b5b9250929050565b60008060208385031215611948576119476117a3565b5b600083013567ffffffffffffffff811115611966576119656117a8565b5b611972858286016118db565b92509250509250929050565b60008115159050919050565b6119938161197e565b82525050565b60006020820190506119ae600083018461198a565b92915050565b6119bd8161197e565b81146119c857600080fd5b50565b6000813590506119da816119b4565b92915050565b6000806000606084860312156119f9576119f86117a3565b5b600084013567ffffffffffffffff811115611a1757611a166117a8565b5b611a23868287016117b2565b935050602084013567ffffffffffffffff811115611a4457611a436117a8565b5b611a50868287016117b2565b9250506040611a61868287016119cb565b9150509250925092565b600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b611aa882611860565b810181811067ffffffffffffffff82111715611ac757611ac6611a70565b5b80604052505050565b6000611ada611799565b9050611ae68282611a9f565b919050565b600080fd5b600067ffffffffffffffff821115611b0b57611b0a611a70565b5b602082029050602081019050919050565b611b2581611685565b8114611b3057600080fd5b50565b600081359050611b4281611b1c565b92915050565b6000611b5b611b5684611af0565b611ad0565b90508083825260208201905060208402830185811115611b7e57611b7d6118d6565b5b835b81811015611ba75780611b938882611b33565b845260208401935050602081019050611b80565b5050509392505050565b600082601f830112611bc657611bc56118cc565b5b8135611bd6848260208601611b48565b91505092915050565b600060208284031215611bf557611bf4611a6b565b5b611bff6020611ad0565b9050600082013567ffffffffffffffff811115611c1f57611c1e611aeb565b5b611c2b84828501611bb1565b60008301525092915050565b600067ffffffffffffffff821115611c5257611c51611a70565b5b602082029050602081019050919050565b600080fd5b600067ffffffffffffffff821115611c8357611c82611a70565b5b611c8c82611860565b9050602081019050919050565b82818337600083830152505050565b6000611cbb611cb684611c68565b611ad0565b905082815260208101848484011115611cd757611cd6611c63565b5b611ce2848285611c99565b509392505050565b600082601f830112611cff57611cfe6118cc565b5b8135611d0f848260208601611ca8565b91505092915050565b6000611d2b611d2684611c37565b611ad0565b90508083825260208201905060208402830185811115611d4e57611d4d6118d6565b5b835b81811015611d9557803567ffffffffffffffff811115611d7357611d726118cc565b5b808601611d808982611cea565b85526020850194505050602081019050611d50565b5050509392505050565b600082601f830112611db457611db36118cc565b5b8135611dc4848260208601611d18565b91505092915050565b600060408284031215611de357611de2611a6b565b5b611ded6040611ad0565b9050600082013567ffffffffffffffff811115611e0d57611e0c611aeb565b5b611e1984828501611bdf565b600083015250602082013567ffffffffffffffff811115611e3d57611e3c611aeb565b5b611e4984828501611d9f565b60208301525092915050565b6000611e613683611dcd565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b60006002820490506001821680611eaf57607f821691505b602082108103611ec257611ec1611e68565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b600060088302611f2a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82611eed565b611f348683611eed565b95508019841693508086168417925050509392505050565b6000819050919050565b611f5f83611699565b611f73611f6b82611f4c565b848454611efa565b825550505050565b600090565b611f88611f7b565b611f93818484611f56565b505050565b5b81811015611fb757611fac600082611f80565b600181019050611f99565b5050565b601f821115611ffc57611fcd81611ec8565b611fd684611edd565b81016020851015611fe5578190505b611ff9611ff185611edd565b830182611f98565b50505b505050565b600082821c905092915050565b600061201f60001984600802612001565b1980831691505092915050565b6000612038838361200e565b9150826002028217905092915050565b6120518261181a565b67ffffffffffffffff81111561206a57612069611a70565b5b6120748254611e97565b61207f828285611fbb565b600060209050601f8311600181146120b257600084156120a0578287015190505b6120aa858261202c565b865550612112565b601f1984166120c086611ec8565b60005b828110156120e8578489015182556001820191506020850194506020810190506120c3565b868310156121055784890151612101601f89168261200e565b8355505b6001600288020188555050505b505050505050565b7f4d50435f434f52453a20494e56414c49445f494e5055545f5445585400000000600082015250565b6000612150601c83611825565b915061215b8261211a565b602082019050919050565b6000602082019050818103600083015261217f81612143565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006121ef82611685565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203612221576122206121b5565b5b600182019050919050565b600061223782611685565b915061224283611685565b925082820261225081611685565b91508282048414831517612267576122666121b5565b5b5092915050565b600061227982611685565b915061228483611685565b925082820190508082111561229c5761229b6121b5565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006122dc82611685565b91506122e783611685565b9250826122f7576122f66122a2565b5b828204905092915050565b600061230d82611685565b915061231883611685565b925082612328576123276122a2565b5b828206905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60007fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b61239781612362565b82525050565b6123a681611685565b82525050565b60006040820190506123c1600083018561238e565b6123ce602083018461239d565b9392505050565b6123de81611685565b81146123e957600080fd5b50565b6000815190506123fb816123d5565b92915050565b600060208284031215612417576124166117a3565b5b6000612425848285016123ec565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60006124558261242e565b61245f8185612439565b935061246f818560208601611836565b61247881611860565b840191505092915050565b6000606082019050612498600083018661238e565b6124a5602083018561239d565b81810360408301526124b7818461244a565b9050949350505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006124ec826124c1565b9050919050565b60008160601b9050919050565b600061250b826124f3565b9050919050565b600061251d82612500565b9050919050565b612535612530826124e1565b612512565b82525050565b60006125478284612524565b60148201915081905092915050565b60007fffffff000000000000000000000000000000000000000000000000000000000082169050919050565b61258b81612556565b82525050565b60006060820190506125a66000830186612582565b6125b3602083018561239d565b6125c0604083018461239d565b94935050505056fea2646970667358221220d6e0439a0689e3ec96d1de87477316624e0cc35f8ee1a2bd731719e3d61ab03e64736f6c63430008140033";

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
