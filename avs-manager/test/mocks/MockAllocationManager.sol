// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IAllocationManager, IAllocationManagerTypes } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IAVSRegistrar } from "eigenlayer/interfaces/IAVSRegistrar.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { OperatorSet } from "eigenlayer/libraries/OperatorSetLib.sol";

contract MockAllocationManager {
    event AVSMetadataURIUpdated(address indexed avs, string metadataURI);
    event OperatorSetCreated(uint32 indexed operatorSetId);

    mapping(address avs => IAVSRegistrar) public avsRegistrar;
    mapping(address avs => bool) public avsRegisteredMetadata;
    mapping(address operator => bool) public registeredOperators;
    mapping(bytes32 operatorSetKey => bool) public operatorSets;
    mapping(bytes32 operatorSetMemberKey => bool) public operatorSetMembers;

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

        // Set operator set membership
        for (uint256 i = 0; i < params.operatorSetIds.length; i++) {
            bytes32 key = keccak256(abi.encodePacked(msg.sender, params.avs, params.operatorSetIds[i]));
            operatorSetMembers[key] = true;
        }

        IAVSRegistrar registrar = avsRegistrar[params.avs];
        if (address(registrar) == address(0)) {
            registrar = IAVSRegistrar(params.avs);
        }

        registrar.registerOperator(msg.sender, params.avs, params.operatorSetIds, params.data);
    }

    function registerForOperatorSets(
        address operator,
        IAllocationManagerTypes.RegisterParams calldata params
    ) external {
        require(address(avsRegistrar[params.avs]) != address(0) || params.avs != address(0), "Invalid AVS");

        registeredOperators[operator] = true;

        // Set operator set membership
        for (uint256 i = 0; i < params.operatorSetIds.length; i++) {
            bytes32 key = keccak256(abi.encodePacked(operator, params.avs, params.operatorSetIds[i]));
            operatorSetMembers[key] = true;
        }

        IAVSRegistrar registrar = avsRegistrar[params.avs];
        if (address(registrar) == address(0)) {
            registrar = IAVSRegistrar(params.avs);
        }

        registrar.registerOperator(operator, params.avs, params.operatorSetIds, params.data);
    }

    function deregisterFromOperatorSets(IAllocationManagerTypes.DeregisterParams calldata params) external {
        registeredOperators[params.operator] = false;

        // Remove operator set membership
        for (uint256 i = 0; i < params.operatorSetIds.length; i++) {
            bytes32 key = keccak256(abi.encodePacked(params.operator, params.avs, params.operatorSetIds[i]));
            operatorSetMembers[key] = false;
        }

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

    function addStrategiesToOperatorSet(address avs, uint32 operatorSetId, IStrategy[] calldata strategies) external {
        // Mock implementation - no actual logic needed for tests
    }

    function removeStrategiesFromOperatorSet(address avs, uint32 operatorSetId, IStrategy[] calldata strategies) external {
        // Mock implementation - no actual logic needed for tests
    }

    function isMemberOfOperatorSet(address operator, OperatorSet memory operatorSet) external view returns (bool) {
        bytes32 key = keccak256(abi.encodePacked(operator, operatorSet.avs, operatorSet.id));
        return operatorSetMembers[key];
    }

    function isOperatorSet(OperatorSet memory operatorSet) external view returns (bool) {
        bytes32 key = keccak256(abi.encodePacked(operatorSet.avs, operatorSet.id));
        return operatorSets[key];
    }

    // Helper function to set operator set membership for testing
    function setOperatorSetMember(
        address operator,
        address avs,
        uint32 operatorSetId,
        bool isMember
    ) external {
        bytes32 key = keccak256(abi.encodePacked(operator, avs, operatorSetId));
        operatorSetMembers[key] = isMember;
    }

    // Helper function to set operator set existence for testing
    function setOperatorSetExists(address avs, uint32 operatorSetId, bool exists) external {
        bytes32 key = keccak256(abi.encodePacked(avs, operatorSetId));
        operatorSets[key] = exists;
    }
}
