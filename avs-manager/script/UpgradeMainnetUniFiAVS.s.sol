// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { DeployerHelper } from "./DeployerHelper.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAllocationManager } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_DAO } from "./Roles.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { console } from "forge-std/console.sol";

contract UpgradeMainnetUniFiAVS is BaseScript, DeployerHelper {
    function run() public {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = _getEigenPodManager();
        address eigenDelegationManager = _getEigenDelegationManager();
        address allocationManager = _getAllocationManager();
        address uniFiAVSManagerProxy = _getUnifyAVSManagerProxy();
        address rewardsCoordinator = _getRewardsCoordinator();

        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAllocationManager(allocationManager),
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

        bytes[] memory calldatas = new bytes[](2);
        bytes4[] memory daoSelectors = new bytes4[](6);
        daoSelectors[0] = UniFiAVSManager.setAllowlistRestakingStrategy.selector;
        daoSelectors[1] = UniFiAVSManager.setCommitmentDelay.selector;
        daoSelectors[2] = UniFiAVSManager.createOperatorSet.selector;
        daoSelectors[3] = UniFiAVSManager.setCurrentOperatorSetId.selector;
        daoSelectors[4] = UniFiAVSManager.addStrategiesToOperatorSet.selector;
        daoSelectors[5] = UniFiAVSManager.removeStrategiesFromOperatorSet.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, address(uniFiAVSManagerProxy), daoSelectors, ROLE_ID_DAO
        );

        bytes4[] memory operationsMultisigSelectors = new bytes4[](2);
        operationsMultisigSelectors[0] = UniFiAVSManager.submitOperatorRewards.selector;
        operationsMultisigSelectors[1] = UniFiAVSManager.setClaimerFor.selector;

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(uniFiAVSManagerProxy),
            operationsMultisigSelectors,
            ROLE_ID_OPERATIONS_MULTISIG
        );

        for (uint256 i = 0; i < calldatas.length; i++) {
            console.log("Calldata:");
            console.logBytes(calldatas[i]);
            console.log("----------------------------------------");
        }
    }
}
