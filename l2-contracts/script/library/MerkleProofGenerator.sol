// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { BLS } from "../../src/library/BLS.sol";
import { BLSG1Decompressor } from "./BLSG1Decompressor.sol";
import { Merkle } from "murky/Merkle.sol";

library MerkleProofGenerator {
    struct MerkleProofData {
        bytes32 blsPubkeyHash;
        address token;
        uint256 amount;
    }

    /**
     * @notice Generates a Merkle root from BLS public keys, token addresses, and amounts
     * @param blsPubkeys Array of BLS public keys
     * @param tokenAddresses Array of token addresses
     * @param amounts Array of amounts corresponding to each BLS public key
     * @return root The Merkle root
     */
    function generateMerkleRoot(bytes[] memory blsPubkeys, address[] memory tokenAddresses, uint256[] memory amounts)
        public
        returns (bytes32 root)
    {
        require(
            blsPubkeys.length == tokenAddresses.length && tokenAddresses.length == amounts.length,
            "Input arrays must have same length"
        );

        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](blsPubkeys.length);

        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            bytes32 blsPubkeyHash = calculateBlsPubKeyHash(blsPubkeys[i]);
            merkleProofDatas[i] = MerkleProofData(blsPubkeyHash, tokenAddresses[i], amounts[i]);
        }

        return buildMerkleRoot(merkleProofDatas);
    }

    /**
     * @notice Generates Merkle proofs for all validators
     * @param blsPubkeys Array of BLS public keys
     * @param tokenAddresses Array of token addresses
     * @param amounts Array of amounts corresponding to each BLS public key
     * @return proofs Array of proofs for each validator
     */
    function generateProofs(bytes[] memory blsPubkeys, address[] memory tokenAddresses, uint256[] memory amounts)
        public
        returns (bytes32[][] memory proofs)
    {
        require(
            blsPubkeys.length == tokenAddresses.length && tokenAddresses.length == amounts.length,
            "Input arrays must have same length"
        );

        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](blsPubkeys.length);
        proofs = new bytes32[][](blsPubkeys.length);

        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            bytes32 blsPubkeyHash = calculateBlsPubKeyHash(blsPubkeys[i]);
            merkleProofDatas[i] = MerkleProofData(blsPubkeyHash, tokenAddresses[i], amounts[i]);
        }

        for (uint256 i = 0; i < merkleProofDatas.length; i++) {
            proofs[i] = generateProof(merkleProofDatas, i);
        }

        return proofs;
    }

    function calculateBlsPubKeyHash(bytes memory validatorPubkey) public view returns (bytes32) {
        BLS.G1Point memory decompressedPoint = BLSG1Decompressor.decompressG1(validatorPubkey);
        return keccak256(
            abi.encodePacked(decompressedPoint.x_a, decompressedPoint.x_b, decompressedPoint.y_a, decompressedPoint.y_b)
        );
    }

    function buildMerkleRoot(MerkleProofData[] memory merkleProofDatas) internal returns (bytes32 root) {
        Merkle merkle = new Merkle();
        bytes32[] memory leaves = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory data = merkleProofDatas[i];
            leaves[i] = keccak256(bytes.concat(keccak256(abi.encode(data.blsPubkeyHash, data.token, data.amount))));
        }

        root = merkle.getRoot(leaves);
    }

    function generateProof(MerkleProofData[] memory merkleProofDatas, uint256 index)
        internal
        returns (bytes32[] memory)
    {
        Merkle merkle = new Merkle();
        bytes32[] memory leaves = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory data = merkleProofDatas[i];
            leaves[i] = keccak256(bytes.concat(keccak256(abi.encode(data.blsPubkeyHash, data.token, data.amount))));
        }

        return merkle.getProof(leaves, index);
    }
}
