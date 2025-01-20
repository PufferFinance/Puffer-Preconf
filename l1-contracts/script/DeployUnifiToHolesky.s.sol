// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { DeployEverything } from "./DeployEverything.s.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";
import { console } from "forge-std/console.sol";

contract DeployUnifiToHolesky is BaseScript {
    function run() public {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = 0x30770d7E3e71112d7A6b7259542D1f680a70e315;
        address eigenDelegationManager = 0xA44151489861Fe9e3055d95adC98FbD462B948e7;
        address avsDirectory = 0x055733000064333CaDDbC92763c58BF0192fFeBf;
        address rewardsCoordinator = 0xAcc1fb458a1317E886dB376Fc8141540537E68fE;
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
