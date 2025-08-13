// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IAllocationManager } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { console } from "forge-std/console.sol";
import { IPauserRegistry } from "eigenlayer/interfaces/IPauserRegistry.sol";

import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { DelegationManagerMock } from "../test/mocks/DelegationManagerMock.sol";
import { MockRewardsCoordinator } from "../test/mocks/MockRewardsCoordinator.sol";
import { MockStrategyManager } from "../test/mocks/MockStrategyManager.sol";
import { MockAllocationManager } from "../test/mocks/MockAllocationManager.sol";

contract DeployUniFiAVSManagerWithMocks is BaseScript {
    UniFiAVSManager public uniFiAVSManagerProxy;
    AccessManager accessManager;
    address eigenPodManager;
    address eigenDelegationManager;
    address allocationManager;
    address rewardsCoordinator;
    uint64 initialCommitmentDelay = 0;

    function run() public broadcast returns (address, address) {
        eigenPodManager = address(new EigenPodManagerMock(IPauserRegistry(address(0))));
        eigenDelegationManager = address(new DelegationManagerMock());
        allocationManager = address(new MockAllocationManager());
        IStrategyManager strategyManager = IStrategyManager(address(new MockStrategyManager()));
        rewardsCoordinator = address(new MockRewardsCoordinator(strategyManager));
        accessManager = new AccessManager(_broadcaster);

        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAllocationManager(allocationManager),
            IRewardsCoordinator(rewardsCoordinator)
        );

        uniFiAVSManagerProxy = UniFiAVSManager(
            address(
                new ERC1967Proxy{ salt: bytes32("UniFiAVSManager") }(
                    address(uniFiAVSManagerImplementation),
                    abi.encodeCall(UniFiAVSManager.initializeV2, (address(accessManager), initialCommitmentDelay))
                )
            )
        );

        console.log("UniFiAVSManager proxy:", address(uniFiAVSManagerProxy));
        console.log("UniFiAVSManager implementation:", address(uniFiAVSManagerImplementation));

        console.log("accessManager:", address(uniFiAVSManagerImplementation));
        console.log("eigenPodManager mock:", address(eigenPodManager));
        console.log("eigenDelegationManager mock:", address(eigenDelegationManager));
        console.log("allocationManager mock:", address(allocationManager));

        return (address(uniFiAVSManagerImplementation), address(uniFiAVSManagerProxy));
    }
}
