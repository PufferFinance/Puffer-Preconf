// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./ContractAddressManager.s.sol";

abstract contract DeploymentScript is Script, ContractAddressManager {
    // Add any common state variables here

    function run() public {
        vm.startBroadcast();

        // Pre-deployment actions
        preDeploymentActions();

        // Deployment
        deploy();

        // Post-deployment actions
        postDeploymentActions();

        vm.stopBroadcast();
    }

    function preDeploymentActions() internal virtual {
        // Read necessary contract addresses
        // Example:
        // address someContract = readAddress("SomeContract");
    }

    function deploy() internal virtual {
        // Implement the actual deployment logic
        // This function should be overridden in the specific deployment scripts
    }

    function postDeploymentActions() internal virtual {
        // Write new contract addresses
        // Example:
        // writeAddress("NewContract", address(newContract));

        // Setup ACL for the contract selectors
        setupAccessControl();
    }

    function setupAccessControl() internal virtual {
        // Setup ACL for the deployed contracts
    }
}
