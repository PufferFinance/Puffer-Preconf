// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployUniFiAVSManager is BaseScript {
    UniFiAVSManager public uniFiAVSManagerProxy;

    function run(address accessManager, address eigenPodManager, address eigenDelegationManager, address avsDirectory)
        public
        broadcast
        returns (address, address)
    {
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

        // console.log("UniFiAVSManager proxy:", address(uniFiAVSManagerProxy));
        // console.log("UniFiAVSManager implementation:", address(uniFiAVSManagerImplementation));

        return (address(uniFiAVSManagerImplementation), address(uniFiAVSManagerProxy));
    }
}
