// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { DeployerHelper } from "./DeployerHelper.s.sol";
import { AccessManager } from "@openzeppelin-v5/contracts/access/manager/AccessManager.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_DAO } from "./Roles.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { console } from "forge-std/console.sol";

contract UpgradeMainnetUniFiAVS is BaseScript, DeployerHelper {
    function run() public {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = _getEigenPodManager();
        address eigenDelegationManager = _getEigenDelegationManager();
        address avsDirectory = _getAVSDirectory();
        address uniFiAVSManagerProxy = _getUnifyAVSManagerProxy();
        address rewardsCoordinator = _getRewardsCoordinator();

        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAVSDirectory(avsDirectory),
            IRewardsCoordinator(rewardsCoordinator)
        );

        console.log("UniFiAVSManager Implementation:", address(uniFiAVSManagerImplementation));

        bytes memory upgradeCalldata = abi.encodeWithSelector(
            UUPSUpgradeable.upgradeToAndCall.selector, address(uniFiAVSManagerImplementation), ""
        );

        bytes memory opsCallData =
            abi.encodeWithSelector(AccessManager.execute.selector, uniFiAVSManagerProxy, upgradeCalldata);
        console.log("Upgrade calldata:");
        console.logBytes(opsCallData);
        console.log("----------------------------------------");

        console.log("Access control calldata:");

        bytes memory calldatas;
        bytes4[] memory daoSelectors = new bytes4[](1);
        daoSelectors[0] = UniFiAVSManager.setAllowlistRestakingStrategy.selector;

        calldatas = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, address(uniFiAVSManagerProxy), daoSelectors, ROLE_ID_DAO
        );

        bytes4[] memory operationsMultisigSelectors = new bytes4[](2);
        operationsMultisigSelectors[0] = UniFiAVSManager.submitOperatorRewards.selector;
        operationsMultisigSelectors[1] = UniFiAVSManager.setClaimerFor.selector;

        calldatas = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(uniFiAVSManagerProxy),
            operationsMultisigSelectors,
            ROLE_ID_OPERATIONS_MULTISIG
        );

        console.logBytes(calldatas);
    }
}
