// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { console } from "forge-std/console.sol";

contract DeployUniFiAVSManager is BaseScript {
    UniFiAVSManager public uniFiAVSManagerProxy;

    function run(address accessManager, address eigenPodManager, address eigenDelegationManager, address avsDirectory)
        public
        returns (address, address)
    {
        vm.startBroadcast(_deployerPrivateKey);
        UniFiAVSManager uniFiAVSManagerImplementation = new UniFiAVSManager(
            IEigenPodManager(eigenPodManager), IDelegationManager(eigenDelegationManager), IAVSDirectory(avsDirectory)
        );

        uniFiAVSManagerProxy = UniFiAVSManager(
            address(
                new ERC1967Proxy{ salt: bytes32("UniFiAVSManager") }(
                    address(uniFiAVSManagerImplementation), abi.encodeCall(UniFiAVSManager.initialize, (accessManager))
                )
            )
        );
        vm.stopBroadcast();

        return (address(uniFiAVSManagerImplementation), address(uniFiAVSManagerProxy));
    }
}
