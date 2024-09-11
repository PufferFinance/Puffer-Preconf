// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";

/**
 * @title Base Script
 * @author Puffer Finance
 */
abstract contract BaseScript is Script {
    uint256 internal PK = 0xa990c824d7f6928806d93674ef4acd4b240ad60c9ce575777c87b36f9a3c32a8; // makeAddr("pufferDeployer")

    // Anvil and `forge test` environment share the same chainId
    // Our shell-scripts/deploy_puffer_protocol.sh is setting this env variable
    // So that we can adapt our deployment for local testing
    bool internal _localAnvil = vm.envOr("IS_LOCAL_ANVIL", false);

    /**
     * @dev Deployer private key is in `PK` env variable
     */
    uint256 internal _deployerPrivateKey = vm.envOr("PK", PK);
    address internal _broadcaster = vm.addr(_deployerPrivateKey);

    constructor() {
        // For local chain (ANVIL) hardcode the deployer as first account from the blockchain
        if (isAnvil()) {
            // Fist account from ANVIL
            _deployerPrivateKey = uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);
            _broadcaster = vm.addr(_deployerPrivateKey);
        }
    }

    modifier broadcast() {
        vm.startBroadcast(_deployerPrivateKey);
        _;
        vm.stopBroadcast();
    }

    function isMainnet() internal view returns (bool) {
        return (block.chainid == 1);
    }

    function isHolesky() internal view returns (bool) {
        return (block.chainid == 17000);
    }

    function isAnvil() internal view returns (bool) {
        return (block.chainid == 31337);
    }
}
