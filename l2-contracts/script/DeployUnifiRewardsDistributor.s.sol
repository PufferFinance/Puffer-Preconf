// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { DeployerHelper } from "./DeployerHelper.s.sol";
import { UnifiRewardsDistributor } from "../src/UnifiRewardsDistributor.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Deploy Unifi Rewards Distributor
 * @author Puffer Finance
 */
contract DeployUnifiRewardsDistributor is DeployerHelper {
    function run() external broadcast {
        // Read the deployer private key from environment variable
        uint256 deployerPk = vm.envUint("PK");
        address owner = vm.addr(deployerPk);
        
        // Deploy the UnifiRewardsDistributor
        UnifiRewardsDistributor rewardsDistributor = new UnifiRewardsDistributor(owner);
        
        // Log the deployment
        console.log("UnifiRewardsDistributor deployed at:", address(rewardsDistributor));
        vm.label(address(rewardsDistributor), "UnifiRewardsDistributor");
    }
} 