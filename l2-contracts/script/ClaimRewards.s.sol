// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { UnifiRewardsDistributor } from "../src/UnifiRewardsDistributor.sol";

import { CSVParser } from "./library/CSVParser.sol";
import { MerkleProofGenerator } from "./library/MerkleProofGenerator.sol";
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

contract ClaimRewards is Script {
    string constant CSV_FILE_PATH = "script/bls_keys.csv";

    /**
     * @notice Reads BLS keys, token addresses, and amounts from a CSV file, generates proofs, and claims rewards
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     */
    function run(address payable distributorAddress) external {
        // Load BLS keys, token addresses, and amounts from CSV file
        (bytes[] memory blsPubkeys, address[] memory tokenAddresses, uint256[] memory amounts) =
            CSVParser.loadBlsKeysAndAmounts(vm, CSV_FILE_PATH);

        // Generate BLS pubkey hashes
        bytes32[] memory blsPubkeyHashes = new bytes32[](blsPubkeys.length);
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            blsPubkeyHashes[i] = MerkleProofGenerator.calculateBlsPubKeyHash(blsPubkeys[i]);
        }

        // Generate proofs
        bytes32[][] memory proofs = MerkleProofGenerator.generateProofs(blsPubkeys, tokenAddresses, amounts);

        // Start the script execution
        vm.startBroadcast();

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));

        // Group claims by token to avoid duplicate claims
        address[] memory uniqueTokens = getUniqueTokens(tokenAddresses);

        for (uint256 t = 0; t < uniqueTokens.length; t++) {
            address token = uniqueTokens[t];

            // Count validators for this token
            uint256 validatorCount = 0;
            for (uint256 i = 0; i < tokenAddresses.length; i++) {
                if (tokenAddresses[i] == token) {
                    validatorCount++;
                }
            }

            // Create arrays for this token's validators
            bytes32[] memory tokenBlsPubkeyHashes = new bytes32[](validatorCount);
            uint256[] memory tokenAmounts = new uint256[](validatorCount);
            bytes32[][] memory tokenProofs = new bytes32[][](validatorCount);

            // Fill arrays
            uint256 index = 0;
            for (uint256 i = 0; i < tokenAddresses.length; i++) {
                if (tokenAddresses[i] == token) {
                    tokenBlsPubkeyHashes[index] = blsPubkeyHashes[i];
                    tokenAmounts[index] = amounts[i];
                    tokenProofs[index] = proofs[i];
                    index++;
                }
            }

            // Claim rewards for this token
            distributor.claimRewards(token, tokenBlsPubkeyHashes, tokenAmounts, tokenProofs);
        }

        vm.stopBroadcast();

        // Display the claimed rewards data
        console.log("Claimed rewards for the following validators:");
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            console.log("Validator", i);
            console.logBytes(blsPubkeys[i]);
            console.log("Hash:");
            console.logBytes32(blsPubkeyHashes[i]);
            console.log("Token:", tokenAddresses[i]);
            console.log("Amount:", amounts[i]);
        }
    }

    /**
     * @notice Get unique token addresses from an array
     * @param tokenAddresses Array of token addresses
     * @return uniqueTokens Array of unique token addresses
     */
    function getUniqueTokens(address[] memory tokenAddresses) internal pure returns (address[] memory uniqueTokens) {
        // First, count the number of unique tokens
        uint256 uniqueCount = 0;
        address[] memory tempTokens = new address[](tokenAddresses.length);

        for (uint256 i = 0; i < tokenAddresses.length; i++) {
            bool isNew = true;
            for (uint256 j = 0; j < uniqueCount; j++) {
                if (tempTokens[j] == tokenAddresses[i]) {
                    isNew = false;
                    break;
                }
            }

            if (isNew) {
                tempTokens[uniqueCount] = tokenAddresses[i];
                uniqueCount++;
            }
        }

        // Create the final array with the correct size
        uniqueTokens = new address[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; i++) {
            uniqueTokens[i] = tempTokens[i];
        }

        return uniqueTokens;
    }
}
