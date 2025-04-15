export const UnifiRewardsDistributorAbi = [
  {
    type: "constructor",
    inputs: [
      {
        name: "initialOwner",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "MERKLE_ROOT_DELAY",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "NEGATED_G1_GENERATOR",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "tuple",
        internalType: "struct BLS.G1Point",
        components: [
          {
            name: "x_a",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "x_b",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "y_a",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "y_b",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
      },
    ],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "REWARDS_DISTRIBUTION_TYPEHASH",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "acceptOwnership",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "cancelPendingMerkleRoot",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "claimRewards",
    inputs: [
      {
        name: "blsPubkeyHashes",
        type: "bytes32[]",
        internalType: "bytes32[]",
      },
      {
        name: "amounts",
        type: "uint256[]",
        internalType: "uint256[]",
      },
      {
        name: "proofs",
        type: "bytes32[][]",
        internalType: "bytes32[][]",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "eip712Domain",
    inputs: [],
    outputs: [
      {
        name: "fields",
        type: "bytes1",
        internalType: "bytes1",
      },
      {
        name: "name",
        type: "string",
        internalType: "string",
      },
      {
        name: "version",
        type: "string",
        internalType: "string",
      },
      {
        name: "chainId",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "verifyingContract",
        type: "address",
        internalType: "address",
      },
      {
        name: "salt",
        type: "bytes32",
        internalType: "bytes32",
      },
      {
        name: "extensions",
        type: "uint256[]",
        internalType: "uint256[]",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getBlsPubkeyHash",
    inputs: [
      {
        name: "pubkeyG1",
        type: "tuple",
        internalType: "struct BLS.G1Point",
        components: [
          {
            name: "x_a",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "x_b",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "y_a",
            type: "bytes32",
            internalType: "bytes32",
          },
          {
            name: "y_b",
            type: "bytes32",
            internalType: "bytes32",
          },
        ],
      },
    ],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    stateMutability: "pure",
  },
  {
    type: "function",
    name: "getChainId",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getClaimer",
    inputs: [
      {
        name: "blsPubkeyHash",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getMerkleRoot",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getMessageHash",
    inputs: [
      {
        name: "claimer",
        type: "address",
        internalType: "address",
      },
      {
        name: "pubkeyHash",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "merkleRoot",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "nonces",
    inputs: [
      {
        name: "pubkeyHash",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "nonce",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "owner",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "pendingMerkleRoot",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "pendingMerkleRootActivationTimestamp",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "pendingOwner",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "registerClaimer",
    inputs: [
      {
        name: "claimer",
        type: "address",
        internalType: "address",
      },
      {
        name: "params",
        type: "tuple[]",
        internalType:
          "struct IUnifiRewardsDistributor.PubkeyRegistrationParams[]",
        components: [
          {
            name: "signature",
            type: "tuple",
            internalType: "struct BLS.G2Point",
            components: [
              {
                name: "x_c0_a",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "x_c0_b",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "x_c1_a",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "x_c1_b",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "y_c0_a",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "y_c0_b",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "y_c1_a",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "y_c1_b",
                type: "bytes32",
                internalType: "bytes32",
              },
            ],
          },
          {
            name: "publicKey",
            type: "tuple",
            internalType: "struct BLS.G1Point",
            components: [
              {
                name: "x_a",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "x_b",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "y_a",
                type: "bytes32",
                internalType: "bytes32",
              },
              {
                name: "y_b",
                type: "bytes32",
                internalType: "bytes32",
              },
            ],
          },
        ],
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "renounceOwnership",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setNewMerkleRoot",
    inputs: [
      {
        name: "newMerkleRoot",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "transferOwnership",
    inputs: [
      {
        name: "newOwner",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validatorClaimedAmount",
    inputs: [
      {
        name: "blsPubkeyHash",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "claimedAmount",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "validatorClaimer",
    inputs: [
      {
        name: "blsPubkeyHash",
        type: "bytes32",
        internalType: "bytes32",
      },
    ],
    outputs: [
      {
        name: "claimer",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "ClaimerSet",
    inputs: [
      {
        name: "blsPubkeyHash",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "claimer",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "EIP712DomainChanged",
    inputs: [],
    anonymous: false,
  },
  {
    type: "event",
    name: "MerkleRootSet",
    inputs: [
      {
        name: "newMerkleRoot",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "activationTimestamp",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "OwnershipTransferStarted",
    inputs: [
      {
        name: "previousOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "newOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "OwnershipTransferred",
    inputs: [
      {
        name: "previousOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "newOwner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "PendingMerkleRootCancelled",
    inputs: [
      {
        name: "merkleRoot",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RewardsClaimed",
    inputs: [
      {
        name: "blsPubkeyHash",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "amount",
        type: "uint256",
        indexed: true,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "error",
    name: "AddressInsufficientBalance",
    inputs: [
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "error",
    name: "BadBLSSignature",
    inputs: [],
  },
  {
    type: "error",
    name: "CannotRegisterZeroPubKey",
    inputs: [],
  },
  {
    type: "error",
    name: "ClaimerNotSet",
    inputs: [],
  },
  {
    type: "error",
    name: "FailedInnerCall",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidInput",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidProof",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidShortString",
    inputs: [],
  },
  {
    type: "error",
    name: "MerkleRootCannotBeZero",
    inputs: [],
  },
  {
    type: "error",
    name: "NothingToClaim",
    inputs: [],
  },
  {
    type: "error",
    name: "OwnableInvalidOwner",
    inputs: [
      {
        name: "owner",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "error",
    name: "OwnableUnauthorizedAccount",
    inputs: [
      {
        name: "account",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "error",
    name: "StringTooLong",
    inputs: [
      {
        name: "str",
        type: "string",
        internalType: "string",
      },
    ],
  },
];
