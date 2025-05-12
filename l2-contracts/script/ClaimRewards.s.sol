// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/UnifiRewardsDistributor.sol";

contract ClaimRewards is Script {
    struct ClaimData {
        bytes32 blsPubkeyHash;
        uint256 amount;
        bytes32[] proof;
    }

    // Original function with struct type - needed for internal code organization
    function _claimRewards(address distributorAddress, ClaimData[] calldata claimData) internal {
        require(claimData.length > 0, "No claim data provided");

        // Group claim data by claimer to ensure all claims in a single transaction have the same claimer
        bytes32[] memory blsPubkeyHashes = new bytes32[](claimData.length);
        uint256[] memory amounts = new uint256[](claimData.length);
        bytes32[][] memory proofs = new bytes32[][](claimData.length);

        for (uint256 i = 0; i < claimData.length; i++) {
            blsPubkeyHashes[i] = claimData[i].blsPubkeyHash;
            amounts[i] = claimData[i].amount;
            proofs[i] = claimData[i].proof;
        }

        // Start the script execution (will use the private key set via PRIVATE_KEY env var)
        vm.startBroadcast();

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));
        
        // Claim rewards
        distributor.claimRewards(blsPubkeyHashes, amounts, proofs);

        vm.stopBroadcast();
    }
    
    // Function with flattened signature for forge script compatibility
    function run(
        address payable distributorAddress,
        bytes32[] calldata blsPubkeyHashes,
        uint256[] calldata amounts,
        bytes32[][] calldata proofs
    ) external {
        require(blsPubkeyHashes.length == amounts.length && amounts.length == proofs.length, "Input arrays must have same length");
        
        // Start the script execution
        vm.startBroadcast();

        // Get the UnifiRewardsDistributor contract
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));
        
        // Claim rewards
        distributor.claimRewards(blsPubkeyHashes, amounts, proofs);

        vm.stopBroadcast();
    }

    // Helper function to verify all claims have the same claimer before executing
    function verifySameClaimer(
        address distributorAddress,
        bytes32[] calldata blsPubkeyHashes
    ) external view returns (bool, address) {
        require(blsPubkeyHashes.length > 0, "No claim data provided");
        
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));
        
        address firstClaimer = distributor.validatorClaimer(blsPubkeyHashes[0]);
        
        for (uint256 i = 1; i < blsPubkeyHashes.length; i++) {
            address claimer = distributor.validatorClaimer(blsPubkeyHashes[i]);
            if (claimer != firstClaimer) {
                return (false, address(0));
            }
        }
        
        return (true, firstClaimer);
    }

    // Helper function to check how much can be claimed for each validator
    function checkClaimableAmounts(
        address payable distributorAddress,
        bytes32[] calldata blsPubkeyHashes,
        uint256[] calldata amounts
    ) external view returns (uint256[] memory) {
        require(blsPubkeyHashes.length == amounts.length, "Input arrays must have same length");
        
        UnifiRewardsDistributor distributor = UnifiRewardsDistributor(payable(distributorAddress));
        uint256[] memory claimableAmounts = new uint256[](blsPubkeyHashes.length);
        
        for (uint256 i = 0; i < blsPubkeyHashes.length; i++) {
            uint256 claimedSoFar = distributor.validatorClaimedAmount(blsPubkeyHashes[i]);
            if (amounts[i] > claimedSoFar) {
                claimableAmounts[i] = amounts[i] - claimedSoFar;
            } else {
                claimableAmounts[i] = 0;
            }
        }
        
        return claimableAmounts;
    }
} 