// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import { Roles } from "./library/Roles.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Grant Roles Script
 * @author Puffer Finance
 */
contract GrantRoles is Script {
    function grantMerkleRootPosterRole(address accessManager) external {
        // Read from .env or command line arguments
        address posterAddress;
        try vm.envAddress("MERKLE_ROOT_POSTER") returns (address envAddress) {
            posterAddress = envAddress;
        } catch {
            posterAddress = msg.sender;
        }

        vm.startBroadcast();

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(Roles.MERKLE_ROOT_POSTER_ROLE, posterAddress, 0);

        console.log("Granted MERKLE_ROOT_POSTER_ROLE to:", posterAddress);

        vm.stopBroadcast();
    }

    function grantMerkleRootCancellerRole(address accessManager) external {
        // Read from .env or command line arguments
        address cancellerAddress;
        try vm.envAddress("MERKLE_ROOT_CANCELLER") returns (address envAddress) {
            cancellerAddress = envAddress;
        } catch {
            cancellerAddress = msg.sender;
        }

        vm.startBroadcast();

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(Roles.MERKLE_ROOT_CANCELLER_ROLE, cancellerAddress, 0);

        console.log("Granted MERKLE_ROOT_CANCELLER_ROLE to:", cancellerAddress);

        vm.stopBroadcast();
    }

    function grantFundsRescuerRole(address accessManager) external {
        // Read from .env or command line arguments
        address rescuerAddress;
        try vm.envAddress("FUNDS_RESCUER") returns (address envAddress) {
            rescuerAddress = envAddress;
        } catch {
            rescuerAddress = msg.sender;
        }

        vm.startBroadcast();

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(Roles.FUNDS_RESCUER_ROLE, rescuerAddress, 0);

        console.log("Granted FUNDS_RESCUER_ROLE to:", rescuerAddress);

        vm.stopBroadcast();
    }

    function grantAllRoles(address accessManager) external {
        // Read from .env or command line arguments
        address posterAddress;
        try vm.envAddress("MERKLE_ROOT_POSTER") returns (address envAddress) {
            posterAddress = envAddress;
        } catch {
            posterAddress = msg.sender;
        }

        address cancellerAddress;
        try vm.envAddress("MERKLE_ROOT_CANCELLER") returns (address envAddress) {
            cancellerAddress = envAddress;
        } catch {
            cancellerAddress = msg.sender;
        }

        address rescuerAddress;
        try vm.envAddress("FUNDS_RESCUER") returns (address envAddress) {
            rescuerAddress = envAddress;
        } catch {
            rescuerAddress = msg.sender;
        }

        vm.startBroadcast();

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(Roles.MERKLE_ROOT_POSTER_ROLE, posterAddress, 0);
        manager.grantRole(Roles.MERKLE_ROOT_CANCELLER_ROLE, cancellerAddress, 0);
        manager.grantRole(Roles.FUNDS_RESCUER_ROLE, rescuerAddress, 0);

        console.log("Granted MERKLE_ROOT_POSTER_ROLE to:", posterAddress);
        console.log("Granted MERKLE_ROOT_CANCELLER_ROLE to:", cancellerAddress);
        console.log("Granted FUNDS_RESCUER_ROLE to:", rescuerAddress);

        vm.stopBroadcast();
    }

    /**
     * @notice Labels all roles on-chain with human-readable names
     * @param accessManager The AccessManager contract address
     */
    function labelAllRoles(address accessManager) external {
        vm.startBroadcast();

        AccessManager manager = AccessManager(accessManager);
        manager.labelRole(Roles.MERKLE_ROOT_POSTER_ROLE, "Merkle Root Poster");
        manager.labelRole(Roles.MERKLE_ROOT_CANCELLER_ROLE, "Merkle Root Canceller");
        manager.labelRole(Roles.FUNDS_RESCUER_ROLE, "Funds Rescuer");

        console.log("Labeled MERKLE_ROOT_POSTER_ROLE as: Merkle Root Poster");
        console.log("Labeled MERKLE_ROOT_CANCELLER_ROLE as: Merkle Root Canceller");
        console.log("Labeled FUNDS_RESCUER_ROLE as: Funds Rescuer");

        vm.stopBroadcast();
    }
}
