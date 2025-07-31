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

import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { MockDelegationManager } from "../test/mocks/MockDelegationManager.sol";
import { MockAVSDirectory } from "../test/mocks/MockAVSDirectory.sol";
import { MockRewardsCoordinator } from "../test/mocks/MockRewardsCoordinator.sol";
import { MockStrategyManager } from "../test/mocks/MockStrategyManager.sol";

contract DeployUniFiAVSManagerWithMocks is BaseScript {
    UniFiAVSManager public uniFiAVSManagerProxy;
    AccessManager accessManager;
    address eigenPodManager;
    address eigenDelegationManager;
    address avsDirectory;
    address rewardsCoordinator;
    uint64 initialDeregistrationDelay = 0;

    function run() public broadcast returns (address, address) {
        eigenPodManager = address(new EigenPodManagerMock());
        eigenDelegationManager = address(new MockDelegationManager());
        avsDirectory = address(new MockAVSDirectory());
        IStrategyManager strategyManager = IStrategyManager(address(new MockStrategyManager()));
        rewardsCoordinator = address(new MockRewardsCoordinator(strategyManager));
        accessManager = new AccessManager(_broadcaster);

        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAllocationManager(avsDirectory),
            IRewardsCoordinator(rewardsCoordinator)
        );

        uniFiAVSManagerProxy = UniFiAVSManager(
            address(
                new ERC1967Proxy{ salt: bytes32("UniFiAVSManager") }(
                    address(uniFiAVSManagerImplementation),
                    abi.encodeCall(UniFiAVSManager.initialize, (address(accessManager), initialDeregistrationDelay))
                )
            )
        );

        console.log("UniFiAVSManager proxy:", address(uniFiAVSManagerProxy));
        console.log("UniFiAVSManager implementation:", address(uniFiAVSManagerImplementation));

        console.log("accessManager:", address(uniFiAVSManagerImplementation));
        console.log("eigenPodManager mock:", address(eigenPodManager));
        console.log("eigenDelegationManager mock:", address(eigenDelegationManager));
        console.log("avsDirectory mock:", address(avsDirectory));

        return (address(uniFiAVSManagerImplementation), address(uniFiAVSManagerProxy));
    }
}
