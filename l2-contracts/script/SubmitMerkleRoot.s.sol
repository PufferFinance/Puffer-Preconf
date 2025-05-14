// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { UnifiRewardsDistributor } from "../src/UnifiRewardsDistributor.sol";

import { CSVParser } from "./library/CSVParser.sol";
import { MerkleProofGenerator } from "./library/MerkleProofGenerator.sol";
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

contract SubmitMerkleRoot is Script {
    string constant CSV_FILE_PATH = "script/bls_keys.csv";

    /**
     * @notice Reads BLS keys and amounts from a CSV file, generates a Merkle root,
     * and sets it on the UnifiRewardsDistributor contract
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     */
    function run(address distributorAddress) external {
        // Load BLS keys and amounts from CSV file
        (bytes[] memory blsPubkeys, uint256[] memory amounts) = CSVParser.loadBlsKeysAndAmounts(vm, CSV_FILE_PATH);

        // Generate the Merkle root
        bytes32 merkleRoot = MerkleProofGenerator.generateMerkleRoot(blsPubkeys, amounts);
        require(merkleRoot != bytes32(0), "Merkle root cannot be zero");

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));

        // Start the script execution
        vm.startBroadcast();

        // Set the new Merkle root
        distributor.setNewMerkleRoot(merkleRoot);

        vm.stopBroadcast();

        // Report when the Merkle root will be activated
        uint256 activationTimestamp = block.timestamp + distributor.MERKLE_ROOT_DELAY();

        console.log("New Merkle root submitted:");
        console.logBytes32(merkleRoot);
        console.log("Activation timestamp:", activationTimestamp);

        // Convert timestamp to human-readable date/time (UTC)
        string memory dateTime = vm.toString(activationTimestamp);
        console.log("Will be active after (UTC):", dateTime);

        // Display the loaded data
        console.log("Loaded validator data:");
        for (uint256 i = 0; i < blsPubkeys.length; i++) {
            console.log("Validator", i);
            console.logBytes(blsPubkeys[i]);
            console.log("Amount:", amounts[i]);
        }
    }

    /**
     * @notice Cancels a pending Merkle root
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     */
    function cancelPendingRoot(address payable distributorAddress) external {
        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));

        // Get the pending Merkle root before cancelling
        bytes32 pendingRoot = distributor.pendingMerkleRoot();

        // Start the script execution
        vm.startBroadcast();

        // Cancel the pending Merkle root
        distributor.cancelPendingMerkleRoot();

        vm.stopBroadcast();

        console.log("Cancelled pending Merkle root:");
        console.logBytes32(pendingRoot);
    }

    /**
     * @notice Checks the status of Merkle roots in the distributor
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     */
    function checkRootStatus(address payable distributorAddress) external view {
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(distributorAddress);

        bytes32 currentRoot = distributor.merkleRoot();
        bytes32 pendingRoot = distributor.pendingMerkleRoot();
        uint256 activationTimestamp = distributor.pendingMerkleRootActivationTimestamp();
        bytes32 activeRoot = distributor.getMerkleRoot();

        console.log("Current root:");
        console.logBytes32(currentRoot);

        console.log("Pending root:");
        console.logBytes32(pendingRoot);

        console.log("Activation timestamp:", activationTimestamp);

        if (activationTimestamp > 0) {
            if (block.timestamp > activationTimestamp) {
                console.log("Pending root is active");
            } else {
                uint256 timeLeft = activationTimestamp - block.timestamp;
                console.log("Time until activation:", timeLeft, "seconds");
            }
        }

        console.log("Currently active root (used for verification):");
        console.logBytes32(activeRoot);
    }
}
