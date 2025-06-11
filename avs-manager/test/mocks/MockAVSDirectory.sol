// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";

contract MockAVSDirectory {
    event AVSMetadataURIUpdated(address indexed avs, string metadataURI);

    mapping(address operator => bool registered) public registeredOperators;

    function avsOperatorStatus(address, address operator)
        external
        view
        returns (IAVSDirectory.OperatorAVSRegistrationStatus)
    {
        return registeredOperators[operator]
            ? IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
            : IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED;
    }

    function registerOperatorToAVS(address operator, ISignatureUtils.SignatureWithSaltAndExpiry memory) external {
        require(
            registeredOperators[operator] != true, "AVSDirectory.registerOperatorToAVS: operator already registered"
        );

        registeredOperators[operator] = true;
    }

    function deregisterOperatorFromAVS(address operator) external {
        registeredOperators[operator] = false;
    }

    // Mock function to check if an operator is registered
    function isOperatorRegistered(address operator) external view returns (bool) {
        return registeredOperators[operator];
    }

    // Mock function to calculate the operator AVS registration digest hash
    function calculateOperatorAVSRegistrationDigestHash(address operator, address avs, bytes32 salt, uint256 expiry)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(operator, avs, salt, expiry));
    }

    function updateAVSMetadataURI(string calldata metadataURI) external {
        emit AVSMetadataURIUpdated(msg.sender, metadataURI);
    }

    // Implement other functions from IAVSDirectory as needed for testing
}
