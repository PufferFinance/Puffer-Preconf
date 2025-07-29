// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "./BaseScript.s.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { ERC1967Proxy } from "@openzeppelin-v5/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";

contract DeployUniFiAVSManager is BaseScript {
    UniFiAVSManager public uniFiAVSManagerProxy;

    function run(
        address accessManager,
        address eigenPodManager,
        address eigenDelegationManager,
        address avsDirectory,
        address rewardsCoordinator,
        uint64 initialDeregistrationDelay
    ) public returns (address, address) {
        vm.startBroadcast(_deployerPrivateKey);
        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAVSDirectory(avsDirectory),
            IRewardsCoordinator(rewardsCoordinator)
        );

        uniFiAVSManagerProxy = UniFiAVSManager(
            address(
                new ERC1967Proxy{ salt: bytes32("UniFiAVSManager") }(
                    address(uniFiAVSManagerImplementation),
                    abi.encodeCall(UniFiAVSManager.initialize, (accessManager, initialDeregistrationDelay))
                )
            )
        );
        vm.stopBroadcast();

        return (address(uniFiAVSManagerImplementation), address(uniFiAVSManagerProxy));
    }
}
