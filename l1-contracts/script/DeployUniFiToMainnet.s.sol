// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { DeployEverything } from "./DeployEverything.s.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";
import { console } from "forge-std/console.sol";
import { ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_DAO } from "./Roles.sol";

contract DeployUniFiToMainnet is BaseScript {
    function run() public returns (AVSDeployment memory deployment) {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
        address eigenDelegationManager = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
        address avsDirectory = 0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF;
        address opsWallet = 0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d;
        address rewardsCoordinator = 0x7750d328b314EfFa365A0402CcfD489B80B0adda;
        uint64 initialDeregistrationDelay = 0;

        // Deploy everything else
        DeployEverything deployEverything = new DeployEverything();
        deployment = deployEverything.run({
            eigenPodManager: eigenPodManager,
            eigenDelegationManager: eigenDelegationManager,
            avsDirectory: avsDirectory,
            rewardsCoordinator: rewardsCoordinator,
            initialDeregistrationDelay: initialDeregistrationDelay
        });

        vm.startBroadcast(_deployerPrivateKey);
        AccessManager accessManager = AccessManager(deployment.accessManager);
        accessManager.grantRole(accessManager.ADMIN_ROLE(), opsWallet, 0);
        accessManager.grantRole(ROLE_ID_DAO, opsWallet, 0);
        accessManager.grantRole(ROLE_ID_OPERATIONS_MULTISIG, opsWallet, 0);

        accessManager.revokeRole(ROLE_ID_DAO, _broadcaster);
        accessManager.revokeRole(accessManager.ADMIN_ROLE(), _broadcaster);
        vm.stopBroadcast();

        console.log("AccessManager:", address(deployment.accessManager));
        console.log("UniFiAVSManager proxy:", address(deployment.avsManagerProxy));
        console.log("UniFiAVSManager implementation:", address(deployment.avsManagerImplementation));

        console.log("EigenPodManager address:", eigenPodManager);
        console.log("EigenDelegationManager address:", eigenDelegationManager);
        console.log("AVSDirectory address:", avsDirectory);
    }
}
