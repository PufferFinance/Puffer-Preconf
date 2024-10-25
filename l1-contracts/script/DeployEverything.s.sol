// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { DeployUniFiAVSManager } from "script/DeployUniFiAVSManager.s.sol";
import { SetupAccess } from "script/SetupAccess.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { AVSDeployment } from "script/DeploymentStructs.sol";
import { UniFiAVSDisputeManager } from "../src/UniFiAVSDisputeManager.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
/**
 * @title Deploy all protocol contracts
 * @author Puffer Finance
 * @notice Deploys all contracts for the AVS and sets up the access control
 * @dev Example on how to run the script
 *      forge script script/DeployEverything.s.sol:DeployEverything --rpc-url=$RPC_URL --sig 'run()' --broadcast
 */

contract DeployEverything is BaseScript {
    address DAO;

    function run(
        address eigenPodManager,
        address eigenDelegationManager,
        address avsDirectory,
        uint64 initialDeregistrationDelay
    ) public returns (AVSDeployment memory) {
        AVSDeployment memory deployment;

        vm.startBroadcast(_deployerPrivateKey);
        AccessManager accessManager = new AccessManager(_broadcaster);

        // Deploy DisputeManager
        UniFiAVSDisputeManager disputeManagerImplementation = new UniFiAVSDisputeManager();
        address disputeManager = address(
            new ERC1967Proxy{ salt: bytes32("UniFiAVSDisputeManager") }(
                address(disputeManagerImplementation),
                abi.encodeCall(UniFiAVSDisputeManager.initialize, (address(accessManager)))
            )
        );

        vm.stopBroadcast();

        // 1. Deploy AVSManager
        (address avsManagerImplementation, address avsManagerProxy) = new DeployUniFiAVSManager().run(
            address(accessManager),
            eigenPodManager,
            eigenDelegationManager,
            avsDirectory,
            initialDeregistrationDelay,
            disputeManager
        );

        deployment.avsManagerImplementation = avsManagerImplementation;
        deployment.avsManagerProxy = avsManagerProxy;
        deployment.accessManager = address(accessManager);
        deployment.disputeManagerProxy = disputeManager;

        // `anvil` in the terminal
        if (_localAnvil) {
            DAO = _broadcaster;
        } else if (isAnvil()) {
            // Tests environment `forge test ...`
            DAO = makeAddr("DAO");
        } else {
            // Testnet deployments
            DAO = _broadcaster;
        }

        deployment.dao = DAO;

        new SetupAccess().run(deployment, DAO);

        _writeJson(deployment);

        return deployment;
    }

    function _writeJson(AVSDeployment memory deployment) internal {
        string memory obj = "";

        vm.serializeAddress(obj, "avsManagerImplementation", deployment.avsManagerImplementation);
        vm.serializeAddress(obj, "avsManagerProxy", deployment.avsManagerProxy);
        vm.serializeAddress(obj, "accessManager", deployment.accessManager);
        vm.serializeAddress(obj, "disputeManagerImplementation", deployment.disputeManagerImplementation);
        vm.serializeAddress(obj, "disputeManagerProxy", deployment.disputeManagerProxy);
        vm.serializeAddress(obj, "dao", DAO);

        string memory finalJson = vm.serializeString(obj, "", "");
        vm.writeJson(finalJson, "./output/avsDeployment.json");
    }
}
