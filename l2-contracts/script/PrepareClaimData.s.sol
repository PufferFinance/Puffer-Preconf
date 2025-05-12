// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {Merkle} from "murky/Merkle.sol";
import {BLS} from "../src/library/BLS.sol";
import {BLSG1Decompressor} from "./BLSG1.sol";

contract PrepareClaimData is Script {
    struct MerkleProofData {
        bytes32 blsPubkeyHash;
        uint256 amount;
    }

    struct ClaimData {
        bytes32 blsPubkeyHash;
        uint256 amount;
        bytes32[] proof;
    }

    function run(bytes[] calldata blsPubkeys, uint256[] calldata amounts) external {
        require(blsPubkeys.length == amounts.length, "Input arrays must have same length");
        
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](blsPubkeys.length);
        
        console.log("Preparing claim data for", blsPubkeys.length, "validators");
        
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            bytes32 blsPubkeyHash = calculateBlsPubKeyHash(blsPubkeys[i]);
            merkleProofDatas[i] = MerkleProofData(
                blsPubkeyHash,
                amounts[i]
            );
        }

        // Build merkle tree
        Merkle merkle = new Merkle();
        bytes32[] memory leaves = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory data = merkleProofDatas[i];
            leaves[i] = keccak256(bytes.concat(keccak256(abi.encode(data.blsPubkeyHash, data.amount))));
        }

        bytes32 root = merkle.getRoot(leaves);
        
        console.log("Merkle Root:");
        console.logBytes32(root);
        
        // Output the claim data in a format that can be used for the ClaimRewards script
        console.log("Claim Data:");
        console.log("[");
        
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            bytes32[] memory proof = merkle.getProof(leaves, i);
            
            console.log("  {");
            console.log("    \"blsPubkeyHash\": \"");
            console.logBytes32(merkleProofDatas[i].blsPubkeyHash);
            console.log("\",");
            console.log("    \"amount\": ");
            console.log(merkleProofDatas[i].amount);
            console.log(",");
            console.log("    \"proof\": [");
            
            for (uint256 j = 0; j < proof.length; j++) {
                if (j < proof.length - 1) {
                    console.log("      \"");
                    console.logBytes32(proof[j]);
                    console.log("\",");
                } else {
                    console.log("      \"");
                    console.logBytes32(proof[j]);
                    console.log("\"");
                }
            }
            
            if (i < blsPubkeys.length - 1) {
                console.log("    ]");
                console.log("  },");
            } else {
                console.log("    ]");
                console.log("  }");
            }
        }
        
        console.log("]");
    }

    function calculateBlsPubKeyHash(bytes calldata validatorPubkey) public view returns (bytes32) {
        BLS.G1Point memory decompressedPoint = BLSG1Decompressor.decompressG1(validatorPubkey);
        return keccak256(abi.encode(
            decompressedPoint.x_a, 
            decompressedPoint.x_b, 
            decompressedPoint.y_a, 
            decompressedPoint.y_b
        ));
    }
} 