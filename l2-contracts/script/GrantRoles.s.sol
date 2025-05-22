// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import { Script } from "forge-std/Script.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { console } from "forge-std/console.sol";

/**
 * @title Grant Roles Script
 * @author Puffer Finance
 */
contract GrantRoles is Script {
    // Role IDs
    uint64 constant MERKLE_ROOT_POSTER_ROLE = 1;
    uint64 constant MERKLE_ROOT_CANCELLER_ROLE = 2;
    uint64 constant FUNDS_RESCUER_ROLE = 3;

    function grantMerkleRootPosterRole(address accessManager) external {
        // Read from .env or command line arguments
        address posterAddress;
        try vm.envAddress("MERKLE_ROOT_POSTER") returns (address envAddress) {
            posterAddress = envAddress;
        } catch {
            posterAddress = msg.sender;
        }

        uint256 deployerPk = vm.envUint("PK");
        vm.startBroadcast(deployerPk);

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(MERKLE_ROOT_POSTER_ROLE, posterAddress, 0);
        
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

        uint256 deployerPk = vm.envUint("PK");
        vm.startBroadcast(deployerPk);

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(MERKLE_ROOT_CANCELLER_ROLE, cancellerAddress, 0);
        
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

        uint256 deployerPk = vm.envUint("PK");
        vm.startBroadcast(deployerPk);

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(FUNDS_RESCUER_ROLE, rescuerAddress, 0);
        
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

        uint256 deployerPk = vm.envUint("PK");
        vm.startBroadcast(deployerPk);

        AccessManager manager = AccessManager(accessManager);
        manager.grantRole(MERKLE_ROOT_POSTER_ROLE, posterAddress, 0);
        manager.grantRole(MERKLE_ROOT_CANCELLER_ROLE, cancellerAddress, 0);
        manager.grantRole(FUNDS_RESCUER_ROLE, rescuerAddress, 0);
        
        console.log("Granted MERKLE_ROOT_POSTER_ROLE to:", posterAddress);
        console.log("Granted MERKLE_ROOT_CANCELLER_ROLE to:", cancellerAddress);
        console.log("Granted FUNDS_RESCUER_ROLE to:", rescuerAddress);

        vm.stopBroadcast();
    }
} 