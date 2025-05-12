// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/UnifiRewardsDistributor.sol";

contract SubmitMerkleRoot is Script {
    /**
     * @notice Sets a new Merkle root on the UnifiRewardsDistributor contract
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     * @param merkleRoot The new Merkle root to set
     */
    function run(address distributorAddress, bytes32 merkleRoot) external {
        require(merkleRoot != bytes32(0), "Merkle root cannot be zero");

        // Start the script execution
        vm.startBroadcast();

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));
        
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
    }

    /**
     * @notice Cancels a pending Merkle root
     * @param distributorAddress The address of the UnifiRewardsDistributor contract
     */
    function cancelPendingRoot(address payable distributorAddress) external {
        // Start the script execution
        vm.startBroadcast();

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));
        
        // Get the pending Merkle root before cancelling
        bytes32 pendingRoot = distributor.pendingMerkleRoot();
        
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