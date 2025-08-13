// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { DeployerHelper } from "./DeployerHelper.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { DeployEverything } from "./DeployEverything.s.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";
import { console } from "forge-std/console.sol";
import { ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_DAO } from "./Roles.sol";

contract DeployUniFiToMainnet is BaseScript, DeployerHelper {
    function run() public returns (AVSDeployment memory deployment) {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = _getEigenPodManager();
        address eigenDelegationManager = _getEigenDelegationManager();
        address allocationManager = _getAllocationManager();
        address opsWallet = _getOPSMultisig();
        address rewardsCoordinator = _getRewardsCoordinator();
        uint64 initialCommitmentDelay = 0;

        // Deploy everything else
        DeployEverything deployEverything = new DeployEverything();
        deployment = deployEverything.run({
            eigenPodManager: eigenPodManager,
            eigenDelegationManager: eigenDelegationManager,
            allocationManager: allocationManager,
            rewardsCoordinator: rewardsCoordinator,
            initialCommitmentDelay: initialCommitmentDelay
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
        console.log("AllocationManager address:", allocationManager);
    }
}
