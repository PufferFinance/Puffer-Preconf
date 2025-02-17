// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { DeployerHelper } from "./DeployerHelper.s.sol";
import { DeployEverything } from "./DeployEverything.s.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";
import { console } from "forge-std/console.sol";

contract DeployUnifiToHolesky is BaseScript, DeployerHelper {
    function run() public {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = _getEigenPodManager();
        address eigenDelegationManager = _getEigenDelegationManager();
        address avsDirectory = _getAVSDirectory();
        address rewardsCoordinator = _getRewardsCoordinator();
        uint64 initialDeregistrationDelay = 0;

        // Deploy everything else
        DeployEverything deployEverything = new DeployEverything();
        AVSDeployment memory deployment = deployEverything.run({
            eigenPodManager: eigenPodManager,
            eigenDelegationManager: eigenDelegationManager,
            avsDirectory: avsDirectory,
            rewardsCoordinator: rewardsCoordinator,
            initialDeregistrationDelay: initialDeregistrationDelay
        });

        console.log("AccessManager:", address(deployment.accessManager));
        console.log("UniFiAVSManager proxy:", address(deployment.avsManagerProxy));
        console.log("UniFiAVSManager implementation:", address(deployment.avsManagerImplementation));

        console.log("EigenPodManager address:", eigenPodManager);
        console.log("EigenDelegationManager address:", eigenDelegationManager);
        console.log("AVSDirectory address:", avsDirectory);
    }
}
