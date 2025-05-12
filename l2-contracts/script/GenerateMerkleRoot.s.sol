// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {Merkle} from "murky/Merkle.sol";
import {BLS} from "../src/library/BLS.sol";
import {BLSG1Decompressor} from "./BLSG1.sol";

contract GenerateMerkleRoot is Script {
    struct MerkleProofData {
        bytes32 blsPubkeyHash;
        uint256 amount;
    }

    function run(bytes[] calldata blsPubkeys, uint256[] calldata amounts) external {
        require(blsPubkeys.length == amounts.length, "Input arrays must have same length");
        
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](blsPubkeys.length);
        
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            bytes32 blsPubkeyHash = calculateBlsPubKeyHash(blsPubkeys[i]);
            console.log("BLS Pubkey:");
            console.logBytes(blsPubkeys[i]);
            console.log("BLS Pubkey Hash:");
            console.logBytes32(blsPubkeyHash);
            merkleProofDatas[i] = MerkleProofData(
                blsPubkeyHash,
                amounts[i]
            );
        }

        bytes32 root = buildMerkleRoot(merkleProofDatas);
        
        console.log("Merkle Root:");
        console.logBytes32(root);
        
        // Generate and output proofs for each validator
        for (uint i = 0; i < merkleProofDatas.length; i++) {
            bytes32[] memory proof = generateProof(merkleProofDatas, i);
            
            console.log("Proof for validator", i);
            console.log("BLS Pubkey:");
            console.logBytes(blsPubkeys[i]);
            console.log("BLS Pubkey Hash:");
            console.logBytes32(merkleProofDatas[i].blsPubkeyHash);
            console.log("Amount:", merkleProofDatas[i].amount);
            console.log("Proof:");
            for (uint j = 0; j < proof.length; j++) {
                console.logBytes32(proof[j]);
            }
            console.log("---");
        }
    }

    function calculateBlsPubKeyHash(bytes calldata validatorPubkey) public view returns (bytes32) {
        BLS.G1Point memory decompressedPoint = BLSG1Decompressor.decompressG1(validatorPubkey);
        return keccak256(abi.encodePacked(decompressedPoint.x_a, decompressedPoint.x_b, decompressedPoint.y_a, decompressedPoint.y_b));
    }

    function buildMerkleRoot(MerkleProofData[] memory merkleProofDatas) internal returns (bytes32 root) {
        Merkle merkle = new Merkle();
        bytes32[] memory leaves = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory data = merkleProofDatas[i];
            leaves[i] = keccak256(bytes.concat(keccak256(abi.encode(data.blsPubkeyHash, data.amount))));
        }

        root = merkle.getRoot(leaves);
    }
    
    function generateProof(MerkleProofData[] memory merkleProofDatas, uint256 index) internal returns (bytes32[] memory) {
        Merkle merkle = new Merkle();
        bytes32[] memory leaves = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory data = merkleProofDatas[i];
            leaves[i] = keccak256(bytes.concat(keccak256(abi.encode(data.blsPubkeyHash, data.amount))));
        }

        return merkle.getProof(leaves, index);
    }
}