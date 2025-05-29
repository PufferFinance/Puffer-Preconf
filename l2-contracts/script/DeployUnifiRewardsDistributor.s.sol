// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UnifiRewardsDistributor } from "../src/UnifiRewardsDistributor.sol";
import { Roles } from "./library/Roles.sol";

import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Deploy Unifi Rewards Distributor
 * @author Puffer Finance
 */
contract DeployUnifiRewardsDistributor is Script {
    // Events for logging deployments
    event AccessManagerDeployed(address indexed accessManager);
    event RewardsDistributorDeployed(address indexed rewardsDistributor);

    function run() external {
        // Get the deployer address from the broadcast account
        address owner = msg.sender;

        vm.startBroadcast();

        // Deploy the AccessManager with the owner as admin
        AccessManager accessManager = new AccessManager(owner);

        // Deploy the UnifiRewardsDistributor with AccessManager
        UnifiRewardsDistributor rewardsDistributor = new UnifiRewardsDistributor(address(accessManager));

        // Set up function roles in the AccessManager
        bytes4[] memory merkleRootPosterSelectors = new bytes4[](1);
        merkleRootPosterSelectors[0] = UnifiRewardsDistributor.setNewMerkleRoot.selector;

        bytes4[] memory merkleRootCancellerSelectors = new bytes4[](1);
        merkleRootCancellerSelectors[0] = UnifiRewardsDistributor.cancelPendingMerkleRoot.selector;

        bytes4[] memory fundsRescuerSelectors = new bytes4[](1);
        fundsRescuerSelectors[0] = UnifiRewardsDistributor.rescueFunds.selector;

        // Configure role permissions
        accessManager.setTargetFunctionRole(
            address(rewardsDistributor), merkleRootPosterSelectors, Roles.MERKLE_ROOT_POSTER_ROLE
        );

        accessManager.setTargetFunctionRole(
            address(rewardsDistributor), merkleRootCancellerSelectors, Roles.MERKLE_ROOT_CANCELLER_ROLE
        );

        accessManager.setTargetFunctionRole(
            address(rewardsDistributor), fundsRescuerSelectors, Roles.FUNDS_RESCUER_ROLE
        );

        // Log the deployment
        emit AccessManagerDeployed(address(accessManager));
        emit RewardsDistributorDeployed(address(rewardsDistributor));

        console.log("AccessManager deployed at:", address(accessManager));
        console.log("UnifiRewardsDistributor deployed at:", address(rewardsDistributor));
        console.log("Note: Use the grant-roles command to assign roles to addresses");

        // Label the addresses for better tracing
        vm.label(address(accessManager), "AccessManager");
        vm.label(address(rewardsDistributor), "UnifiRewardsDistributor");

        vm.stopBroadcast();
    }
}
