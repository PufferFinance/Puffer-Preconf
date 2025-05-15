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
     * @notice Reads BLS keys and amounts from a CSV file, generates proofs, and claims rewards
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     */
    function run(address payable distributorAddress) external {
        // Load BLS keys and amounts from CSV file
        (bytes[] memory blsPubkeys, uint256[] memory amounts) = CSVParser.loadBlsKeysAndAmounts(vm, CSV_FILE_PATH);

        // Generate BLS pubkey hashes
        bytes32[] memory blsPubkeyHashes = new bytes32[](blsPubkeys.length);
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            blsPubkeyHashes[i] = MerkleProofGenerator.calculateBlsPubKeyHash(blsPubkeys[i]);
        }

        // Generate proofs
        bytes32[][] memory proofs = MerkleProofGenerator.generateProofs(blsPubkeys, amounts);

        // Start the script execution
        vm.startBroadcast();

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));

        // Claim rewards
        distributor.claimRewards(blsPubkeyHashes, amounts, proofs);

        vm.stopBroadcast();

        // Display the claimed rewards data
        console.log("Claimed rewards for the following validators:");
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            console.log("Validator", i);
            console.logBytes(blsPubkeys[i]);
            console.log("Hash:");
            console.logBytes32(blsPubkeyHashes[i]);
            console.log("Amount:", amounts[i]);
        }
    }
}
