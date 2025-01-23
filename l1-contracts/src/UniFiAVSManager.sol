// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessManagedUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IAVSDirectoryExtended } from "./interfaces/EigenLayer/IAVSDirectoryExtended.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IUniFiAVSManager } from "./interfaces/IUniFiAVSManager.sol";
import { UniFiAVSManagerStorage } from "./UniFiAVSManagerStorage.sol";
import { IRewardsCoordinator } from "./interfaces/EigenLayer/IRewardsCoordinator.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./structs/ValidatorData.sol";
import "./structs/OperatorData.sol";

contract UniFiAVSManager is UniFiAVSManagerStorage, IUniFiAVSManager, UUPSUpgradeable, AccessManagedUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    address public constant BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

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
     * @notice The RewardsCoordinator contract
     * @custom:oz-upgrades-unsafe-allow state-variable-immutable
     */
    IRewardsCoordinator public immutable EIGEN_REWARDS_COORDINATOR;
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
        IEigenPodManager eigenPodManagerAddress,
        IDelegationManager eigenDelegationManagerAddress,
        IAVSDirectory avsDirectoryAddress,
        IRewardsCoordinator rewardsCoordinatorAddress
    ) {
        EIGEN_POD_MANAGER = eigenPodManagerAddress;
        EIGEN_DELEGATION_MANAGER = eigenDelegationManagerAddress;
        AVS_DIRECTORY = IAVSDirectoryExtended(address(avsDirectoryAddress));
        EIGEN_REWARDS_COORDINATOR = IRewardsCoordinator(address(rewardsCoordinatorAddress));
        _disableInitializers();
    }

    function initialize(address accessManager, uint64 initialDeregistrationDelay) public initializer {
        __AccessManaged_init(accessManager);
        _setDeregistrationDelay(initialDeregistrationDelay);

        // Initialize BEACON_CHAIN_STRATEGY as an allowed restaking strategy
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        $.allowlistedRestakingStrategies.add(BEACON_CHAIN_STRATEGY);
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
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        emit OperatorRegistered(msg.sender);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerOperatorWithCommitment(
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature,
        OperatorCommitment memory initialCommitment
    ) external restricted {
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operator = $.operators[msg.sender];
        operator.commitment = initialCommitment;

        emit OperatorRegisteredWithCommitment(msg.sender, initialCommitment);
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
        operator.startDeregisterOperatorBlock = 0;
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function deregisterValidators(bytes32[] calldata blsPubKeyHashes) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        uint256 validatorCount = blsPubKeyHashes.length;
        uint64 deregistrationDelay = $.deregistrationDelay;

        for (uint256 i = 0; i < validatorCount; i++) {
            bytes32 blsPubKeyHash = blsPubKeyHashes[i];
            ValidatorData storage validator = $.validators[blsPubKeyHash];

            address operator = validator.operator;

            if (operator != msg.sender) {
                revert NotValidatorOperator();
            }

            if (validator.registeredUntil != type(uint64).max) {
                revert ValidatorAlreadyDeregistered();
            }

            validator.registeredUntil = uint64(block.number) + deregistrationDelay;

            emit ValidatorDeregistered({ operator: operator, blsPubKeyHash: blsPubKeyHash });
        }

        $.operators[msg.sender].validatorCount -= uint128(validatorCount);
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

        operator.startDeregisterOperatorBlock = uint64(block.number);

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
        operator.commitmentValidAfter = uint64(block.number) + $.deregistrationDelay;

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
        _setDeregistrationDelay(newDelay);
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

        emit ChainIDSet(index, chainID);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function updateAVSMetadataURI(string memory _metadataURI) external restricted {
        AVS_DIRECTORY.updateAVSMetadataURI(_metadataURI);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function setAllowlistRestakingStrategy(address strategy, bool allowed) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        bool success;
        if (allowed) {
            success = $.allowlistedRestakingStrategies.add(strategy);
        } else {
            success = $.allowlistedRestakingStrategies.remove(strategy);
        }
        if (success) {
            emit RestakingStrategyAllowlistUpdated(strategy, allowed);
        } else {
            revert RestakingStrategyAllowlistUpdateFailed();
        }
    }

    function submitOperatorRewards(IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions) external restricted {
        uint256 submissionsLength = submissions.length;
        for (uint256 i = 0; i < submissionsLength; i++) {
            IRewardsCoordinator.OperatorDirectedRewardsSubmission memory submission = submissions[i];
            uint256 totalRewards = 0;
            uint256 rewardsLength = submission.operatorRewards.length;
            for (uint256 j = 0; j < rewardsLength; j++) {
                totalRewards += submission.operatorRewards[j].amount;
            }
            IERC20(address(submission.token)).approve(address(EIGEN_REWARDS_COORDINATOR), totalRewards);
        }
        EIGEN_REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(address(this), submissions);

        emit OperatorRewardsSubmitted(submissions);
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
        uint256 blsPubKeyHashesLength = blsPubKeyHashes.length;
        ValidatorDataExtended[] memory validators = new ValidatorDataExtended[](blsPubKeyHashesLength);
        for (uint256 i = 0; i < blsPubKeyHashesLength; i++) {
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
        uint256 count = 0;
        for (uint8 i = 0; i < 255; i++) {
            // Check if the bit at position i+1 is set in the bitmap
            // We use i+1 because index 0 is reserved (not used)
            if ((bitmap & (1 << (i + 1))) != 0) {
                result[count] = $.bitmapIndexToChainId[i + 1];
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
        OperatorCommitment memory activeCommitment = _getActiveCommitment(operator);

        uint8 bitmapIndex = $.chainIdToBitmapIndex[chainId];
        if (bitmapIndex == 0) {
            return false; // ChainId not set
        }

        return (activeCommitment.chainIDBitMap & (1 << (bitmapIndex - 1))) != 0;
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (address[] memory restakedStrategies)
    {
        OperatorDataExtended memory operatorData = _getOperator(operator);
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        if (operatorData.isRegistered) {
            uint256 allowlistedCount = $.allowlistedRestakingStrategies.length();
            IStrategy[] memory strategies = new IStrategy[](allowlistedCount);

            for (uint256 i = 0; i < allowlistedCount; i++) {
                strategies[i] = IStrategy($.allowlistedRestakingStrategies.at(i));
            }

            uint256[] memory shares = EIGEN_DELEGATION_MANAGER.getOperatorShares(operator, strategies);

            uint256 restakedCount = 0;
            restakedStrategies = new address[](allowlistedCount);

            for (uint256 i = 0; i < allowlistedCount; i++) {
                if (shares[i] > 0) {
                    restakedStrategies[restakedCount] = address(strategies[i]);
                    restakedCount++;
                }
            }

            // Resize the array to the actual number of restaked strategies
            assembly {
                mstore(restakedStrategies, restakedCount)
            }
        }
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getRestakeableStrategies() external view returns (address[] memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.allowlistedRestakingStrategies.values();
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function avsDirectory() external view returns (address) {
        return address(AVS_DIRECTORY);
    }

    // INTERNAL FUNCTIONS

    function _getOperator(address operator) internal view returns (OperatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operatorData = $.operators[operator];

        OperatorCommitment memory activeCommitment = _getActiveCommitment(operatorData);

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

            OperatorData storage operator = $.operators[validatorData.operator];
            OperatorCommitment memory activeCommitment = _getActiveCommitment(operator);

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

    function _getActiveCommitment(OperatorData storage operatorData)
        internal
        view
        returns (OperatorCommitment memory)
    {
        if (operatorData.commitmentValidAfter != 0 && block.number >= operatorData.commitmentValidAfter) {
            return operatorData.pendingCommitment;
        }
        return operatorData.commitment;
    }

    /**
     * @dev Internal function to set or update the deregistration delay
     * @param newDelay The new deregistration delay to set
     */
    function _setDeregistrationDelay(uint64 newDelay) internal {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        uint64 oldDelay = $.deregistrationDelay;
        $.deregistrationDelay = newDelay;

        emit DeregistrationDelaySet(oldDelay, newDelay);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
