// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { DeployUniFiAVSManager } from "./DeployUniFiAVSManager.s.sol";
import { SetupAccess } from "./SetupAccess.s.sol";
import { AccessManager } from "@openzeppelin-v5/contracts/access/manager/AccessManager.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";

/**
 * @title Deploy all protocol contracts
 * @author Puffer Finance
 * @notice Deploys all contracts for the AVS and sets up the access control
 * @dev Example on how to run the script
 *      forge script script/DeployEverything.s.sol:DeployEverything --rpc-url=$RPC_URL --sig 'run()' --broadcast
 */
contract DeployEverything is BaseScript {
    address DAO;
    address OPERATIONS_MULTISIG;

    function run(
        address eigenPodManager,
        address eigenDelegationManager,
        address avsDirectory,
        address rewardsCoordinator,
        uint64 initialDeregistrationDelay
    ) public returns (AVSDeployment memory) {
        AVSDeployment memory deployment;

        vm.startBroadcast(_deployerPrivateKey);
        AccessManager accessManager = new AccessManager(_broadcaster);
        vm.stopBroadcast();

        // 1. Deploy AVSManager
        (address avsManagerImplementation, address avsManagerProxy) = new DeployUniFiAVSManager().run({
            accessManager: address(accessManager),
            eigenPodManager: eigenPodManager,
            eigenDelegationManager: eigenDelegationManager,
            avsDirectory: avsDirectory,
            rewardsCoordinator: rewardsCoordinator,
            initialDeregistrationDelay: initialDeregistrationDelay
        });

        deployment.avsManagerImplementation = avsManagerImplementation;
        deployment.avsManagerProxy = avsManagerProxy;
        deployment.accessManager = address(accessManager);

        // `anvil` in the terminal
        if (_localAnvil) {
            DAO = _broadcaster;
            OPERATIONS_MULTISIG = _broadcaster;
        } else if (isAnvil()) {
            // Tests environment `forge test ...`
            DAO = makeAddr("DAO");
            OPERATIONS_MULTISIG = address(0x031337);
        } else {
            // Testnet deployments
            DAO = _broadcaster;
            OPERATIONS_MULTISIG = _broadcaster;
        }

        deployment.dao = DAO;
        deployment.operationsMultisig = OPERATIONS_MULTISIG;
        new SetupAccess().run(deployment, DAO, OPERATIONS_MULTISIG);

        _writeJson(deployment);

        return deployment;
    }

    function _writeJson(AVSDeployment memory deployment) internal {
        string memory obj = "";

        vm.serializeAddress(obj, "avsManagerImplementation", deployment.avsManagerImplementation);
        vm.serializeAddress(obj, "avsManagerProxy", deployment.avsManagerProxy);
        vm.serializeAddress(obj, "accessManager", deployment.accessManager);
        vm.serializeAddress(obj, "dao", DAO);
        vm.serializeAddress(obj, "operationsMultisig", OPERATIONS_MULTISIG);

        string memory finalJson = vm.serializeString(obj, "", "");
        vm.writeJson(finalJson, "./output/avsDeployment.json");
    }
}
