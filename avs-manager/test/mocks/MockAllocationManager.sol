// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IAllocationManager, IAllocationManagerTypes } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IAVSRegistrar } from "eigenlayer/interfaces/IAVSRegistrar.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";

contract MockAllocationManager {
    event AVSMetadataURIUpdated(address indexed avs, string metadataURI);
    event OperatorSetCreated(uint32 indexed operatorSetId);

    mapping(address avs => IAVSRegistrar) public avsRegistrar;
    mapping(address avs => bool) public avsRegisteredMetadata;
    mapping(address operator => bool) public registeredOperators;

    function setAVSRegistrar(address avs, IAVSRegistrar registrar) external {
        avsRegistrar[avs] = registrar;
    }

    function getAVSRegistrar(address avs) external view returns (IAVSRegistrar) {
        if (address(avsRegistrar[avs]) == address(0)) {
            return IAVSRegistrar(avs);
        }
        return avsRegistrar[avs];
    }

    function registerToOperatorSets(IAllocationManagerTypes.RegisterParams calldata params) external {
        require(address(avsRegistrar[params.avs]) != address(0) || params.avs != address(0), "Invalid AVS");

        registeredOperators[msg.sender] = true;

        IAVSRegistrar registrar = avsRegistrar[params.avs];
        if (address(registrar) == address(0)) {
            registrar = IAVSRegistrar(params.avs);
        }

        registrar.registerOperator(msg.sender, params.avs, params.operatorSetIds, params.data);
    }

    function deregisterFromOperatorSets(IAllocationManagerTypes.DeregisterParams calldata params) external {
        registeredOperators[params.operator] = false;

        IAVSRegistrar registrar = avsRegistrar[params.avs];
        if (address(registrar) == address(0)) {
            registrar = IAVSRegistrar(params.avs);
        }

        try registrar.deregisterOperator(params.operator, params.avs, params.operatorSetIds) {
            // Success
        } catch {
            // Ignore failures in deregistration
        }
    }

    function updateAVSMetadataURI(address avs, string calldata metadataURI) external {
        if (!avsRegisteredMetadata[avs]) {
            avsRegisteredMetadata[avs] = true;
        }
        emit AVSMetadataURIUpdated(avs, metadataURI);
    }

    function createOperatorSets(address avs, IAllocationManagerTypes.CreateSetParams[] calldata params) external {
        require(avsRegisteredMetadata[avs], "AVS metadata not registered");

        for (uint256 i = 0; i < params.length; i++) {
            emit OperatorSetCreated(params[i].operatorSetId);
        }
    }

    // Mock function to check if an operator is registered
    function isOperatorRegistered(address operator) external view returns (bool) {
        return registeredOperators[operator];
    }

    // Mock function to calculate the operator registration digest hash
    function calculateOperatorRegistrationDigestHash(address operator, address avs, bytes32 salt, uint256 expiry)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(operator, avs, salt, expiry));
    }
}
