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
import { console } from "forge-std/console.sol";
import { ROLE_ID_OPERATIONS_MULTISIG, ROLE_ID_DAO, ROLE_ID_UNIFI_AVS_MANAGER } from "./Roles.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { UniFiAVSDisputeManager } from "../src/UniFiAVSDisputeManager.sol";
import { IUniFiAVSDisputeManager } from "../src/interfaces/IUniFiAVSDisputeManager.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Multicall } from "@openzeppelin/contracts/utils/Multicall.sol";

contract UpgradeMainnetUniFiAVS is BaseScript {
    function run() public returns (AVSDeployment memory deployment) {
        // Set addresses for EigenLayer contracts
        address eigenPodManager = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
        address eigenDelegationManager = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
        address avsDirectory = 0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF;
        address opsWallet = 0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d;
        address accessManagerAddress = 0x75351d49229aa42Df7fEBfbEa0c7cECC881ad7E7;
        address uniFiAVSManagerProxy = 0x2d86E90ED40a034C753931eE31b1bD5E1970113d;
        uint64 initialDeregistrationDelay = 0;

        AccessManager accessManager = AccessManager(accessManagerAddress);
        // Deploy DisputeManager
        UniFiAVSDisputeManager disputeManagerImplementation = new UniFiAVSDisputeManager();
        address disputeManager = address(
            new ERC1967Proxy{ salt: bytes32("UniFiAVSDisputeManager") }(
                address(disputeManagerImplementation),
                abi.encodeCall(UniFiAVSDisputeManager.initialize, (address(accessManager)))
            )
        );
        console.log("DisputeManager implementation:", address(disputeManagerImplementation));
        console.log("DisputeManager proxy:", disputeManager);

        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAVSDirectory(avsDirectory),
            IUniFiAVSDisputeManager(disputeManager)
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

        bytes[] memory calldatas = new bytes[](3);
        bytes4[] memory uniFiAVSManagerSelectors = new bytes4[](4);
        uniFiAVSManagerSelectors[0] = UniFiAVSManager.registerValidatorsOptimistically.selector;
        uniFiAVSManagerSelectors[1] = UniFiAVSManager.slashValidatorsWithInvalidSignature.selector;
        uniFiAVSManagerSelectors[2] = UniFiAVSManager.slashValidatorsWithInvalidPubkey.selector;
        uniFiAVSManagerSelectors[3] = UniFiAVSManager.slashValidatorsWithInvalidIndex.selector;

        calldatas[0] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(uniFiAVSManagerProxy),
            uniFiAVSManagerSelectors,
            accessManager.PUBLIC_ROLE()
        );

        calldatas[1] = abi.encodeWithSelector(
            AccessManager.grantRole.selector, ROLE_ID_UNIFI_AVS_MANAGER, address(uniFiAVSManagerProxy), 0
        );

        bytes4[] memory disputeManagerSelectors = new bytes4[](1);
        disputeManagerSelectors[0] = IUniFiAVSDisputeManager.slashOperator.selector;

        calldatas[2] = abi.encodeWithSelector(
            AccessManager.setTargetFunctionRole.selector,
            address(disputeManager),
            disputeManagerSelectors,
            ROLE_ID_UNIFI_AVS_MANAGER
        );

        bytes memory multicallData = abi.encodeCall(Multicall.multicall, (calldatas));

        console.logBytes(multicallData);
    }
}
