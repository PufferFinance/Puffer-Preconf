// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessManagedUpgradeable} from "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import {ISignatureUtils} from "eigenlayer/interfaces/ISignatureUtils.sol";
import {IAVSDirectory} from "eigenlayer/interfaces/IAVSDirectory.sol";
import {IDelegationManager} from "eigenlayer/interfaces/IDelegationManager.sol";
import {IEigenPodManager} from "eigenlayer/interfaces/IEigenPodManager.sol";
import {IEigenPod} from "eigenlayer/interfaces/IEigenPod.sol";
import {BN254} from "eigenlayer-middleware/libraries/BN254.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {BLSSingatureCheckerLib} from "./lib/BLSSingatureCheckerLib.sol";
import {IUniFiAVSManager} from "./interfaces/IUniFiAVSManager.sol";
import {UniFiAVSManagerStorage} from "./UniFiAVSManagerStorage.sol";
import "./structs/ValidatorRegistrationParams.sol";
import "./structs/ValidatorData.sol";
import "./structs/OperatorData.sol";

error InvalidOperator();
error OperatorAlreadyRegistered();
error NotPodOwner();

contract UniFiAVSManager is
    UniFiAVSManagerStorage,
    IUniFiAVSManager,
    EIP712,
    UUPSUpgradeable,
    AccessManagedUpgradeable
{
    using BN254 for BN254.G1Point;

    IEigenPodManager public immutable EIGEN_POD_MANAGER;
    IDelegationManager public immutable EIGEN_DELEGATION_MANAGER;
    IAVSDirectory internal immutable AVS_DIRECTORY;

    bytes32 public constant VALIDATOR_REGISTRATION_TYPEHASH =
        keccak256(
            "BN254ValidatorRegistration(bytes32 ecdsaPubKeyHash,bytes32 salt,uint256 expiry)"
        );

    modifier onlyPodOwner() {
        require(EIGEN_POD_MANAGER.hasPod(msg.sender), "Not a pod owner");
        _;
    }

    constructor(
        IEigenPodManager eigenPodManager,
        IDelegationManager eigenDelegationManager,
        IAVSDirectory avsDirectory
    ) EIP712("UniFiAVSManager", "v0.0.1") {
        EIGEN_POD_MANAGER = eigenPodManager;
        EIGEN_DELEGATION_MANAGER = eigenDelegationManager;
        AVS_DIRECTORY = avsDirectory;
        _disableInitializers();
    }

    function initialize(address accessManager) public initializer {
        __AccessManaged_init(accessManager);
    }

    function createOperator(
        string calldata metadataURI,
        address delegationApprover
    ) external onlyPodOwner returns (address) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        if ($.operators[msg.sender].operatorContract != address(0)) {
            revert OperatorAlreadyExists();
        }

        IDelegationManager.OperatorDetails memory operatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: address(this),
            delegationApprover: delegationApprover,
            stakerOptOutWindowBlocks: uint32(65) // todo
        });

        // Register the operator with EigenLayer
        EIGEN_DELEGATION_MANAGER.registerAsOperator(operatorDetails, metadataURI);

        $.operators[msg.sender] = OperatorData({
            operatorContract: msg.sender,
            isRegistered: false,
            isDelegated: false,
            validatorCount: 0
        });

        emit OperatorCreated(msg.sender, msg.sender);

        return msg.sender;
    }

    function registerOperator(
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        address podOwner = RestakingOperator(msg.sender).owner();
        if ($.operators[podOwner].operatorContract != msg.sender) {
            revert InvalidOperator();
        }
        if ($.operators[podOwner].isRegistered) {
            revert OperatorAlreadyRegistered();
        }
        if (!EIGEN_POD_MANAGER.hasPod(podOwner)) {
            revert NotPodOwner();
        }

        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        $.operators[podOwner].isRegistered = true;

        emit OperatorRegistered(msg.sender, podOwner);
    }

    function registerValidator(
        address podOwner,
        ValidatorRegistrationParams calldata params
    ) external {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        IEigenPod eigenPod = EIGEN_POD_MANAGER.getPod(podOwner);
        bytes32 pubkeyHash = BN254.hashG1Point(params.pubkeyG1);

        IEigenPod.ValidatorInfo memory validatorInfo = eigenPod
            .validatorPubkeyHashToInfo(pubkeyHash);

        if (validatorInfo.status != IEigenPod.VALIDATOR_STATUS.ACTIVE) {
            revert ValidatorNotActive();
        }

        if (params.expiry < block.timestamp) {
            revert RegistrationExpired();
        }

        if ($.salts[params.salt]) {
            revert InvalidRegistrationSalt();
        }

        $.salts[params.salt] = true;

        BN254.G1Point memory messageHash = blsMessageHash(
            VALIDATOR_REGISTRATION_TYPEHASH,
            params.ecdsaPubKeyHash,
            params.salt,
            params.expiry
        );

        if (
            !BLSSingatureCheckerLib.isBlsSignatureValid(
                params.pubkeyG1,
                params.pubkeyG2,
                params.registrationSignature,
                messageHash
            )
        ) {
            revert InvalidSignature();
        }

        $.validatorIndexes[validatorInfo.validatorIndex] = pubkeyHash;
        $.validators[pubkeyHash] = ValidatorData({
            ecdsaPubKeyHash: params.ecdsaPubKeyHash,
            eigenPod: address(eigenPod)
        });
        $.operators[msg.sender].validatorCount++;

        emit ValidatorRegistered(podOwner, params.ecdsaPubKeyHash, pubkeyHash);
    }

    function deregisterValidator(bytes32[] calldata blsPubKeyHashs) external {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        for (uint256 i = 0; i < blsPubKeyHashs.length; i++) {
            ValidatorData storage validator = $.validators[blsPubKeyHashs[i]];
            IEigenPod eigenPod = IEigenPod(validator.eigenPod);

            if (
                EIGEN_DELEGATION_MANAGER.delegatedTo(eigenPod.podOwner()) !=
                msg.sender
            ) {
                revert NotDelegatedToOperator();
            }

            OperatorData storage operator = $.operators[msg.sender];

            operator.validatorCount--;
            delete $.validators[blsPubKeyHashs[i]];

            emit ValidatorDeregistered(blsPubKeyHashs[i]);
        }
    }

    function deregisterOperator() external {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.validatorCount > 0) {
            revert OperatorHasValidators();
        }

        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);

        emit OperatorDeregistered(msg.sender);
    }

    function blsMessageHash(
        bytes32 typeHash,
        bytes32 ecdsaPubKeyHash,
        bytes32 salt,
        uint256 expiry
    ) public view returns (BN254.G1Point memory) {
        return
            BN254.hashToG1(
                _hashTypedDataV4(
                    keccak256(
                        abi.encode(typeHash, ecdsaPubKeyHash, salt, expiry)
                    )
                )
            );
    }

    function getValidator(
        bytes32 blsPubKeyHash
    ) external view returns (ValidatorData memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        return $.validators[blsPubKeyHash];
    }

    function getValidator(
        uint256 validatorIndex
    ) external view returns (ValidatorData memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        return $.validators[$.validatorIndexes[validatorIndex]];
    }

    function getOperator(
        address operator
    ) external view returns (OperatorData memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData memory operatorData = $.operators[operator];
        return operatorData;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal virtual override restricted {}
}
