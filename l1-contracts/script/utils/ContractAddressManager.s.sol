// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

contract ContractAddressManager is Script {
    using stdJson for string;

    string private constant OUTPUT_DIR = "output/";
    string private constant FILE_NAME = "contractDeployments.json";

    function writeAddress(string memory contractName, address contractAddress) public {
        string memory filePath = getFilePath();
        string memory json = vm.readFile(filePath);

        if (bytes(json).length == 0) {
            json = "{}";
        }

        json = json.serialize(contractName, contractAddress);
        vm.writeFile(filePath, json);

        console.log("Wrote address for", contractName, ":", contractAddress);
    }

    function readAddress(string memory contractName) public view returns (address) {
        string memory filePath = getFilePath();
        string memory json = vm.readFile(filePath);

        if (bytes(json).length == 0) {
            revert("Contract address file is empty or doesn't exist");
        }

        address contractAddress = json.readAddress(string(abi.encodePacked(".", contractName)));
        return contractAddress;
    }

    function getFilePath() private view returns (string memory) {
        uint256 chainId = block.chainid;
        return string(abi.encodePacked(OUTPUT_DIR, vm.toString(chainId), "/", FILE_NAME));
    }
}
