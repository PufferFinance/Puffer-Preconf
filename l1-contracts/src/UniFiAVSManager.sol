// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessManagedUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IAVSDirectoryExtended } from "./interfaces/EigenLayer/IAVSDirectoryExtended.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IUniFiAVSManager } from "./interfaces/IUniFiAVSManager.sol";
import { UniFiAVSManagerStorage } from "./UniFiAVSManagerStorage.sol";
import "./structs/ValidatorData.sol";
import "./structs/OperatorData.sol";

contract UniFiAVSManager is UniFiAVSManagerStorage, IUniFiAVSManager, UUPSUpgradeable, AccessManagedUpgradeable {
    /**
     * @notice The EigenPodManager
     * @custom:oz-upgrades-unsafe-allow state-variable-immutable
     */
    IEigenPodManager public immutable override EIGEN_POD_MANAGER;
    /**
     * @notice The EigenDelegationManager
     * @custom:oz-upgrades-unsafe-allow state-variable-immutable
     */
    IDelegationManager public immutable override EIGEN_DELEGATION_MANAGER;
    /**
     * @notice The AVSDirectory contract
     * @custom:oz-upgrades-unsafe-allow state-variable-immutable
     */
    IAVSDirectoryExtended public immutable override AVS_DIRECTORY;

    /**
     * @dev Modifier to check if the pod is delegated to the msg.sender
     * @param podOwner The address of the pod owner
     */
    modifier podIsDelegatedToMsgSender(address podOwner) {
        if (!EIGEN_DELEGATION_MANAGER.isOperator(msg.sender)) {
            revert NotOperator();
        }
        if (!EIGEN_POD_MANAGER.hasPod(podOwner)) {
            revert NoEigenPod();
        }
        if (EIGEN_DELEGATION_MANAGER.delegatedTo(podOwner) != msg.sender) {
            revert NotDelegatedToOperator();
        }
        _;
    }

    /**
     * @dev Modifier to check if the operator is registered in the AVS
     * @param operator The address of the operator
     */
    modifier registeredOperator(address operator) {
        if (
            AVS_DIRECTORY.avsOperatorStatus(address(this), operator)
                == IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED
        ) {
            revert OperatorNotRegistered();
        }
        _;
    }

    /**
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor(
        IEigenPodManager eigenPodManager,
        IDelegationManager eigenDelegationManager,
        IAVSDirectory avsDirectory
    ) {
        EIGEN_POD_MANAGER = eigenPodManager;
        EIGEN_DELEGATION_MANAGER = eigenDelegationManager;
        AVS_DIRECTORY = IAVSDirectoryExtended(address(avsDirectory));
        _disableInitializers();
    }

    function initialize(address accessManager) public initializer {
        __AccessManaged_init(accessManager);
    }

    // EXTERNAL FUNCTIONS

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerOperator(ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
        external
        restricted
    {
        if (
            AVS_DIRECTORY.avsOperatorStatus(address(this), msg.sender)
                == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
        ) {
            revert OperatorAlreadyRegistered();
        }

        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        emit OperatorRegistered(msg.sender);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerValidators(address podOwner, bytes32[] calldata blsPubKeyHashes)
        external
        podIsDelegatedToMsgSender(podOwner)
        registeredOperator(msg.sender)
        restricted
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        bytes memory delegateKey = $.operators[msg.sender].commitment.delegateKey;

        if (delegateKey.length == 0) {
            revert DelegateKeyNotSet();
        }

        IEigenPod eigenPod = EIGEN_POD_MANAGER.getPod(podOwner);

        uint256 newValidatorCount = blsPubKeyHashes.length;
        for (uint256 i = 0; i < newValidatorCount; i++) {
            bytes32 blsPubKeyHash = blsPubKeyHashes[i];
            IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyHashToInfo(blsPubKeyHash);

            if (validatorInfo.status != IEigenPod.VALIDATOR_STATUS.ACTIVE) {
                revert ValidatorNotActive();
            }

            if ($.validators[blsPubKeyHash].index != 0) {
                revert ValidatorAlreadyRegistered();
            }

            $.validators[blsPubKeyHash] = ValidatorData({
                eigenPod: address(eigenPod),
                index: validatorInfo.validatorIndex,
                operator: msg.sender,
                registeredUntil: type(uint64).max
            });

            $.validatorIndexes[validatorInfo.validatorIndex] = blsPubKeyHash;

            emit ValidatorRegistered({
                podOwner: podOwner,
                operator: msg.sender,
                delegateKey: delegateKey,
                blsPubKeyHash: blsPubKeyHash,
                validatorIndex: validatorInfo.validatorIndex
            });
        }

        OperatorData storage operator = $.operators[msg.sender];
        operator.validatorCount += uint128(newValidatorCount);
        operator.startDeregisterOperatorBlock = 0; // Reset the deregistration start block
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function deregisterValidators(bytes32[] calldata blsPubKeyHashes) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            bytes32 blsPubKeyHash = blsPubKeyHashes[i];
            ValidatorData storage validator = $.validators[blsPubKeyHash];

            if (validator.index == 0) {
                revert ValidatorNotFound();
            }

            if (validator.operator != msg.sender) {
                // eject if no longer active
                IEigenPod eigenPod = IEigenPod(validator.eigenPod);
                IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyHashToInfo(blsPubKeyHashes[i]);
                if (validatorInfo.status == IEigenPod.VALIDATOR_STATUS.ACTIVE) {
                    revert NotValidatorOperator();
                }

                // update the actual operator's validator count
                $.operators[validator.operator].validatorCount -= 1;
            } else {
                $.operators[msg.sender].validatorCount -= 1;
            }

            validator.registeredUntil = uint64(block.number) + $.deregistrationDelay;

            emit ValidatorDeregistered({
                podOwner: IEigenPod(validator.eigenPod).podOwner(),
                operator: validator.operator,
                delegateKey: $.operators[validator.operator].commitment.delegateKey,
                blsPubKeyHash: blsPubKeyHash,
                validatorIndex: validator.index
            });
        }
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function startDeregisterOperator() external registeredOperator(msg.sender) restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.validatorCount > 0) {
            revert OperatorHasValidators();
        }

        if (operator.startDeregisterOperatorBlock != 0) {
            revert DeregistrationAlreadyStarted();
        }

        operator.startDeregisterOperatorBlock = uint128(block.number);

        emit OperatorDeregisterStarted(msg.sender);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function finishDeregisterOperator() external registeredOperator(msg.sender) restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.startDeregisterOperatorBlock == 0) {
            revert DeregistrationNotStarted();
        }

        if (block.number < operator.startDeregisterOperatorBlock + $.deregistrationDelay) {
            revert DeregistrationDelayNotElapsed();
        }

        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);

        delete $.operators[msg.sender];

        emit OperatorDeregistered(msg.sender);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function setOperatorCommitment(OperatorCommitment memory newCommitment)
        external
        registeredOperator(msg.sender)
        restricted
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operator = $.operators[msg.sender];

        operator.pendingCommitment = newCommitment;
        operator.commitmentValidAfter = uint128(block.number + $.deregistrationDelay);

        emit OperatorCommitmentChangeInitiated(
            msg.sender, operator.commitment, newCommitment, operator.commitmentValidAfter
        );
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function updateOperatorCommitment() external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operator = $.operators[msg.sender];

        if (operator.commitmentValidAfter == 0 || block.number < operator.commitmentValidAfter) {
            revert CommitmentChangeNotReady();
        }

        OperatorCommitment memory oldCommitment = operator.commitment;
        operator.commitment = operator.pendingCommitment;

        // Reset pending data
        delete operator.pendingCommitment;
        delete operator.commitmentValidAfter;

        emit OperatorCommitmentSet(msg.sender, oldCommitment, operator.commitment);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function setDeregistrationDelay(uint64 newDelay) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        uint64 oldDelay = $.deregistrationDelay;
        $.deregistrationDelay = newDelay;
        emit DeregistrationDelaySet(oldDelay, newDelay);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function setChainID(uint8 index, uint256 chainID) external restricted {
        if (index == 0) revert IndexOutOfBounds();

        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        $.bitmapIndexToChainId[index] = chainID;
        $.chainIdToBitmapIndex[chainID] = index;
    }

    // GETTERS

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getDeregistrationDelay() external view returns (uint64) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.deregistrationDelay;
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getOperator(address operator) external view returns (OperatorDataExtended memory) {
        return _getOperator(operator);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getValidator(bytes32 blsPubKeyHash) external view returns (ValidatorDataExtended memory) {
        return _getValidator(blsPubKeyHash);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getValidator(uint256 validatorIndex) external view returns (ValidatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        bytes32 blsPubKeyHash = $.validatorIndexes[validatorIndex];
        return _getValidator(blsPubKeyHash);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getValidators(bytes32[] calldata blsPubKeyHashes) external view returns (ValidatorDataExtended[] memory) {
        ValidatorDataExtended[] memory validators = new ValidatorDataExtended[](blsPubKeyHashes.length);
        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            validators[i] = _getValidator(blsPubKeyHashes[i]);
        }

        return validators;
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function bitmapToChainIDs(uint256 bitmap) public view returns (uint256[] memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        uint256[] memory result = new uint256[](256);
        uint8 count = 0;
        for (uint8 i = 1; i < 255; i++) {
            if ((bitmap & (1 << i)) != 0) {
                result[count] = $.bitmapIndexToChainId[i];
                count++;
            }
        }
        // Resize the array to remove unused elements
        assembly {
            mstore(result, count)
        }
        return result;
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getChainID(uint8 index) external view returns (uint256) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.bitmapIndexToChainId[index];
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getBitmapIndex(uint256 chainID) external view returns (uint8) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        uint8 index = $.chainIdToBitmapIndex[chainID];

        return index; // if 0 then there's no index set
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function isValidatorInChainId(bytes32 blsPubKeyHash, uint256 chainId) external view returns (bool) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        ValidatorData storage validator = $.validators[blsPubKeyHash];

        if (validator.index == 0) {
            return false; // Validator not found
        }

        OperatorData storage operator = $.operators[validator.operator];
        OperatorCommitment memory activeCommitment = operator.commitment;

        uint8 bitmapIndex = $.chainIdToBitmapIndex[chainId];
        if (bitmapIndex == 0) {
            return false; // ChainId not set
        }

        return (activeCommitment.chainIDBitMap & (1 << (bitmapIndex - 1))) != 0;
    }

    // INTERNAL FUNCTIONS

    function _getOperator(address operator) internal view returns (OperatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operatorData = $.operators[operator];

        OperatorCommitment memory activeCommitment = operatorData.commitment;
        if (operatorData.commitmentValidAfter != 0 && block.number >= operatorData.commitmentValidAfter) {
            activeCommitment = operatorData.pendingCommitment;
        }

        return OperatorDataExtended({
            validatorCount: operatorData.validatorCount,
            commitment: activeCommitment,
            pendingCommitment: operatorData.pendingCommitment,
            startDeregisterOperatorBlock: operatorData.startDeregisterOperatorBlock,
            isRegistered: AVS_DIRECTORY.avsOperatorStatus(address(this), operator)
                == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED,
            commitmentValidAfter: operatorData.commitmentValidAfter
        });
    }

    function _getValidator(bytes32 blsPubKeyHash) internal view returns (ValidatorDataExtended memory validator) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        ValidatorData memory validatorData = $.validators[blsPubKeyHash];

        if (validatorData.index != 0) {
            IEigenPod eigenPod = IEigenPod(validatorData.eigenPod);
            IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyHashToInfo(blsPubKeyHash);

            bool backedByStake = EIGEN_DELEGATION_MANAGER.delegatedTo(eigenPod.podOwner()) == validatorData.operator;

            OperatorData storage operatorData = $.operators[validatorData.operator];
            OperatorCommitment memory activeCommitment = operatorData.commitment;
            if (operatorData.commitmentValidAfter != 0 && block.number >= operatorData.commitmentValidAfter) {
                activeCommitment = operatorData.pendingCommitment;
            }

            return ValidatorDataExtended({
                operator: validatorData.operator,
                eigenPod: validatorData.eigenPod,
                validatorIndex: validatorInfo.validatorIndex,
                status: validatorInfo.status,
                delegateKey: activeCommitment.delegateKey,
                chainIDBitMap: activeCommitment.chainIDBitMap,
                backedByStake: backedByStake,
                registered: block.number < validatorData.registeredUntil
            });
        }
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
