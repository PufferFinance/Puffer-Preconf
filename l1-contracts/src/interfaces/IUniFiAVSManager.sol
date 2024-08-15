// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {BN254} from "eigenlayer-middleware/libraries/BN254.sol";
import {IBLSApkRegistry} from "eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import {ISignatureUtils} from "eigenlayer/interfaces/ISignatureUtils.sol";
import "../structs/ValidatorRegistrationParams.sol";
import "../structs/ValidatorData.sol";
import "../structs/OperatorData.sol";

/**
 * @title IUniFiAVSManager
 * @notice Interface for the UniFiAVSManager contract.
 */
interface IUniFiAVSManager {
    error RegistrationExpired();
    error InvalidRegistrationSalt();
    error SignatureExpired();
    error InvalidOperatorSalt();
    error OperatorHasValidators();
    error NotOperator();
    error NoEigenPod();
    error NotDelegatedToOperator();
    error ValidatorNotActive();
    error InvalidSignature();
    error OperatorAlreadyExists();
    error OperatorNotRegistered();
    error OperatorAlreadyRegistered();

    event OperatorCreated(address indexed operator, address indexed podOwner);
    event OperatorRegistered(address indexed operator);
    event ValidatorRegistered(
        address indexed podOwner,
        bytes delegatePubKey,
        bytes32 blsPubKeyHash,
        uint256 validatorIndex
    );
    event OperatorDeregistered(address indexed operator);
    event ValidatorDeregistered(bytes32 blsPubKeyHash);

    function registerOperator(
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external;

    function registerValidator(
        address podOwner,
        ValidatorRegistrationParams calldata params
    ) external;

    function deregisterValidator(bytes32[] calldata blsPubKeyHashs) external;

    function deregisterOperator() external;

    function getValidator(
        bytes32 blsPubKeyHash
    ) external view returns (ValidatorData memory, bool backedByStake);

    function getValidator(
        uint256 validatorIndex
    ) external view returns (ValidatorData memory, bool backedByStake);

    function getOperator(
        address operator
    ) external view returns (OperatorData memory);

    function isDelegatedPodOwner(
        address operator,
        address podOwner
    ) external view returns (bool);
}
