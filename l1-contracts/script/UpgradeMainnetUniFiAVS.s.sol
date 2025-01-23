// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { DeployEverything } from "./DeployEverything.s.sol";
import { AVSDeployment } from "./DeploymentStructs.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IRewardsCoordinator } from "../src/interfaces/EigenLayer/IRewardsCoordinator.sol";
import { console } from "forge-std/console.sol";
import { ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_DAO } from "./Roles.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UpgradeMainnetUniFiAVS is BaseScript {
    function run() public returns (AVSDeployment memory deployment) {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
        address eigenDelegationManager = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
        address avsDirectory = 0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF;
        address opsWallet = 0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d;
        address accessManagerAddress = 0x75351d49229aa42Df7fEBfbEa0c7cECC881ad7E7;
        address uniFiAVSManagerProxy = 0x2d86E90ED40a034C753931eE31b1bD5E1970113d;
        address rewardsCoordinator = 0x7750d328b314EfFa365A0402CcfD489B80B0adda;
        uint64 initialDeregistrationDelay = 0;

        AccessManager accessManager = AccessManager(accessManagerAddress);
        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager), IDelegationManager(eigenDelegationManager), IAVSDirectory(avsDirectory), IRewardsCoordinator(rewardsCoordinator)
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

        bytes4[] memory operationsMultisigSelectors = new bytes4[](1);
        operationsMultisigSelectors[0] = UniFiAVSManager.submitOperatorRewards.selector;

        calldatas = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector, address(uniFiAVSManagerProxy), operationsMultisigSelectors, ROLE_ID_OPERATIONS_MULTISIG
        );

        console.logBytes(calldatas);
    }
}
