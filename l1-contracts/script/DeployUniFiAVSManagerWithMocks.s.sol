// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import "../test/mocks/MockEigenPodManager.sol";
import "../test/mocks/MockDelegationManager.sol";
import "../test/mocks/MockAVSDirectory.sol";
import "../src/UniFiAVSDisputeManager.sol";
import { IUniFiAVSDisputeManager } from "../src/interfaces/IUniFiAVSDisputeManager.sol";
import { console } from "forge-std/console.sol";

contract DeployUniFiAVSManagerWithMocks is BaseScript {
    UniFiAVSManager public uniFiAVSManagerProxy;
    AccessManager accessManager;
    address eigenPodManager;
    address eigenDelegationManager;
    address avsDirectory;
    uint64 initialDeregistrationDelay = 0;
    address disputeManager;

    function run() public broadcast returns (address, address) {
        eigenPodManager = address(new MockEigenPodManager());
        eigenDelegationManager = address(new MockDelegationManager());
        avsDirectory = address(new MockAVSDirectory());

        accessManager = new AccessManager(_broadcaster);
        UniFiAVSDisputeManager disputeManagerImplementation = new UniFiAVSDisputeManager();
        disputeManager = address(
            new ERC1967Proxy{ salt: bytes32("UniFiAVSDisputeManager") }(
                address(disputeManagerImplementation),
                abi.encodeCall(UniFiAVSDisputeManager.initialize, (address(accessManager)))
            )
        );

        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager),
            IDelegationManager(eigenDelegationManager),
            IAVSDirectory(avsDirectory),
            IUniFiAVSDisputeManager(disputeManager)
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
        console.log("disputeManager mock:", address(disputeManager));

        return (address(uniFiAVSManagerImplementation), address(uniFiAVSManagerProxy));
    }
}
