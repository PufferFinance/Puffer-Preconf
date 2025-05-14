// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UnifiRewardsDistributor } from "../src/UnifiRewardsDistributor.sol";
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Deploy Unifi Rewards Distributor
 * @author Puffer Finance
 */
contract DeployUnifiRewardsDistributor is Script {
    function run() external {
        // Read the deployer private key from environment variable
        uint256 deployerPk = vm.envUint("PK");
        address owner = vm.addr(deployerPk);

        vm.startBroadcast(deployerPk);

        // Deploy the UnifiRewardsDistributor
        UnifiRewardsDistributor rewardsDistributor = new UnifiRewardsDistributor(owner);

        // Log the deployment
        console.log("UnifiRewardsDistributor deployed at:", address(rewardsDistributor));
        vm.label(address(rewardsDistributor), "UnifiRewardsDistributor");

        vm.stopBroadcast();
    }
}
