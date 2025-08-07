// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtilsMixin } from "eigenlayer/interfaces/ISignatureUtilsMixin.sol";
import { IAllocationManager } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IAVSRegistrar } from "eigenlayer/interfaces/IAVSRegistrar.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";

/**
 * @title IUniFiAVSManager
 * @notice Interface for the UniFiAVSManager contract, which manages operators and validators in the UniFi AVS.
 * @dev This interface defines the main functions and events for operator and validator management.
 */
interface IUniFiAVSManager is IAVSRegistrar {
    /**
     * @title ValidatorData
     * @notice Struct to store information about a validator in the UniFi AVS system.
     * @dev This struct is used to keep track of important validator details.
     */
    struct ValidatorData {
        /// @notice The address of the EigenPod associated with this validator.
        address eigenPod;
        /// @notice The beacon chain validator index.
        uint64 index;
        /// @notice The address of the operator managing this validator.
        address operator;
        /// @notice The block number until which the validator is registered.
        uint64 registeredUntil;
    }

    /**
     * @title OperatorData
     * @notice Struct to store information about an operator in the UniFi AVS system.
     * @dev This struct is used to keep track of important operator details.
     */
    struct OperatorData {
        /// @notice The current commitment of the operator.
        OperatorCommitment commitment;
        /// @notice The pending commitment of the operator.
        OperatorCommitment pendingCommitment;
        /// @notice The number of validators associated with this operator.
        uint128 validatorCount;
        /// @notice The block number when the operator was deregistered.
        uint64 deregisteredBlockNumber;
        /// @notice The block number after which the pending commitment becomes valid.
        uint64 commitmentValidAfter;
    }

    /**
     * @title ValidatorDataExtended
     * @notice Struct to store comprehensive information about a validator.
     * @dev This struct combines ValidatorData with additional status information.
     */
    struct ValidatorDataExtended {
        /// @notice The address of the operator this validator is delegated to.
        address operator;
        /// @notice The address of the validator's EigenPod.
        address eigenPod;
        /// @notice The index of the validator in the beacon chain.
        uint64 validatorIndex;
        /// @notice The current status of the validator in the EigenPod.
        IEigenPod.VALIDATOR_STATUS status;
        /// @notice The delegate key currently associated with the validator's operator.
        bytes delegateKey;
        /// @notice Chain IDs the validator's operator is committed to.
        uint256[] chainIds;
        /// @notice Indicates whether the validator's EigenPod is currently delegated to the operator.
        bool backedByStake;
        /// @notice Indicates whether the validator is currently registered (current block < registeredUntil).
        bool registered;
    }

    struct OperatorCommitment {
        /// @notice The delegate key for the operator.
        bytes delegateKey;
        /// @notice Chain IDs the operator is committed to.
        uint256[] chainIds;
    }

    /**
     * @title OperatorDataExtended
     * @notice Struct to store extended information about an operator in the UniFi AVS system.
     * @dev This struct combines OperatorData with additional status information.
     */
    struct OperatorDataExtended {
        /// @notice The current commitment of the operator.
        OperatorCommitment commitment;
        /// @notice The pending commitment of the operator.
        OperatorCommitment pendingCommitment;
        /// @notice The number of validators associated with this operator.
        uint128 validatorCount;
        /// @notice The block number after which the pending commitment becomes valid.
        uint128 commitmentValidAfter;
        /// @notice Whether the operator is registered or not.
        bool isRegistered;
    }
    // 7 bytes padding here (automatically added by the compiler)

    /// @notice Thrown when an operator attempts to deregister while still having validators
    error OperatorHasValidators();

    /// @notice Thrown when a non-operator attempts an operator-only action
    error NotOperator();

    /// @notice Thrown when an EigenPod does not exist for a given address
    error NoEigenPod();

    /// @notice Thrown when trying to finish deregistering an operator before the delay has elapsed
    error DeregistrationDelayNotElapsed();

    /// @notice Thrown when attempting to start deregistering an operator that has already started
    error DeregistrationAlreadyStarted();

    /// @notice Thrown when trying to finish deregistering an operator that hasn't started
    error DeregistrationNotStarted();

    /// @notice Thrown when an address is not delegated to the expected operator
    error NotDelegatedToOperator();

    /// @notice Thrown when a validator is not in the active state
    error ValidatorNotActive();

    /// @notice Thrown when an action requires a registered operator, but the operator is not registered
    error OperatorNotRegistered();

    /// @notice Thrown when a non-operator attempts to deregister a validator
    error NotValidatorOperator();

    /// @notice Thrown when attempting to register a validator that is already registered
    error ValidatorAlreadyRegistered();

    /// @notice Thrown when an operator's delegate key is not set
    error DelegateKeyNotSet();

    /// @notice Thrown when attempting to deregister a validator that is not registered
    error ValidatorNotRegistered();

    /// @notice Thrown when a restaking strategy allowlist update fails
    error RestakingStrategyAllowlistUpdateFailed();

    /// @notice Thrown when an operator registration call fails
    error OperatorRegistrationCallFailed();

    /// @notice Thrown when an invalid EigenPodManager address is provided
    error InvalidEigenPodManagerAddress();

    /// @notice Thrown when an invalid EigenDelegationManager address is provided
    error InvalidEigenDelegationManagerAddress();

    /// @notice Thrown when an invalid AllocationManager address is provided
    error InvalidAllocationManagerAddress();

    /// @notice Thrown when an invalid RewardsCoordinator address is provided
    error InvalidRewardsCoordinatorAddress();

    /// @notice Thrown when an operator is in the deregistration process and attempts to perform restricted actions
    error OperatorInDeregistrationProcess();

    /// @notice Thrown when an unsupported AVS address is provided
    error UnsupportedAVS();

    /// @notice Thrown when invalid operator set IDs are provided
    error InvalidOperatorSetIds();

    /// @notice Thrown when caller is not the AllocationManager
    error OnlyAllocationManager();

    /// @notice Thrown when an invalid AVS address is provided
    error InvalidAVSAddress();

    /// @notice Thrown when an invalid number of operator sets are provided for registration
    error InvalidOperatorSetsProvided();

    /// @notice Thrown when an invalid operator set ID is provided
    error InvalidOperatorSetId();

    /// @notice Thrown when an operator set does not exist
    error OperatorSetDoesNotExist();

    /**
     * @notice Emitted when a new operator is registered in the UniFi AVS.
     * @param operator The address of the registered operator.
     * @param operatorSetIds The operator set IDs the operator registered for.
     */
    event OperatorRegistered(address indexed operator, uint32[] operatorSetIds);

    /**
     * @notice Emitted when a new operator is registered in the UniFi AVS with a commitment.
     * @param operator The address of the registered operator.
     * @param operatorSetIds The operator set IDs the operator registered for.
     * @param commitment The commitment set for the operator.
     */
    event OperatorRegisteredWithCommitment(
        address indexed operator, uint32[] operatorSetIds, OperatorCommitment commitment
    );

    /**
     * @notice Emitted when a new validator is registered in the UniFi AVS .
     * @param podOwner The address of the validator's EigenPod owner.
     * @param delegateKey The delegate public key for the validator.
     * @param validatorPubkey The BLS public key of the validator.
     * @param validatorIndex The beacon chain validator index.
     */
    event ValidatorRegistered(
        address indexed podOwner,
        address indexed operator,
        bytes delegateKey,
        bytes validatorPubkey,
        uint256 validatorIndex
    );

    /**
     * @notice Emitted when an operator starts the deregistration process.
     * @param operator The address of the operator starting deregistration.
     */
    event OperatorDeregisterStarted(address indexed operator);

    /**
     * @notice Emitted when an operator is deregistered from the UniFi AVS.
     * @param operator The address of the deregistered operator.
     * @param operatorSetIds The operator set IDs the operator was deregistered from.
     */
    event OperatorDeregistered(address indexed operator, uint32[] operatorSetIds);

    /**
     * @notice Emitted when a validator is deregistered from the UniFi AVS.
     * @param operator The address of the operator managing the validator.
     * @param validatorPubkey The BLS public key of the deregistered validator.
     */
    event ValidatorDeregistered(address indexed operator, bytes validatorPubkey);

    /**
     * @notice Emitted when an operator's commitment is set or updated.
     * @param operator The address of the operator.
     * @param oldCommitment The previous commitment for the operator.
     * @param newCommitment The new commitment for the operator.
     */
    event OperatorCommitmentSet(
        address indexed operator, OperatorCommitment oldCommitment, OperatorCommitment newCommitment
    );

    /**
     * @notice Emitted when an operator's commitment is changed.
     * @param operator The address of the operator.
     * @param oldCommitment The previous commitment for the operator.
     * @param newCommitment The new commitment for the operator.
     * @param validAfter The block number after which the new commitment becomes valid.
     */
    event OperatorCommitmentChangeInitiated(
        address indexed operator, OperatorCommitment oldCommitment, OperatorCommitment newCommitment, uint128 validAfter
    );

    /**
     * @notice Emitted when the commitment delay is updated.
     * @param oldDelay The previous commitment delay value.
     * @param newDelay The new commitment delay value.
     */
    event CommitmentDelaySet(uint64 oldDelay, uint64 newDelay);

    /**
     * @notice Emitted when a restaking strategy is added or removed from the allowlist.
     * @param strategy The address of the strategy.
     * @param allowed Whether the strategy is allowed (true) or disallowed (false).
     */
    event RestakingStrategyAllowlistUpdated(address indexed strategy, bool allowed);

    /**
     * @notice Emitted when operator rewards are submitted.
     */
    event OperatorRewardsSubmitted();

    /**
     * @notice Emitted when an operator set is created.
     * @param operatorSetId The ID of the created operator set.
     */
    event OperatorSetCreated(uint32 indexed operatorSetId);

    /**
     * @notice Emitted when strategies are added to an operator set.
     * @param operatorSetId The ID of the operator set.
     * @param strategies The strategies that were added.
     */
    event StrategiesAddedToOperatorSet(uint32 indexed operatorSetId, IStrategy[] strategies);

    /**
     * @notice Emitted when strategies are removed from an operator set.
     * @param operatorSetId The ID of the operator set.
     * @param strategies The strategies that were removed.
     */
    event StrategiesRemovedFromOperatorSet(uint32 indexed operatorSetId, IStrategy[] strategies);

    /**
     * @notice Emitted when the current operator set ID is set.
     * @param operatorSetId The ID of the operator set.
     */
    event CurrentOperatorSetIdSet(uint32 indexed operatorSetId);

    /**
     * @notice Returns the EigenPodManager contract.
     * @return IEigenPodManager The EigenPodManager contract.
     */
    function EIGEN_POD_MANAGER() external view returns (IEigenPodManager);

    /**
     * @notice Returns the EigenDelegationManager contract.
     * @return IDelegationManager The EigenDelegationManager contract.
     */
    function EIGEN_DELEGATION_MANAGER() external view returns (IDelegationManager);

    /**
     * @notice Returns the AllocationManager contract.
     * @return IAllocationManager The AllocationManager contract.
     */
    function ALLOCATION_MANAGER() external view returns (IAllocationManager);

    // IAVSRegistrar functions are inherited - registerOperator, deregisterOperator, supportsAVS

    /**
     * @notice Registers validators for a given pod owner.
     * @param podOwner The address of the pod owner.
     * @param validatorPubkeys The BLS public keys of the validators to register.
     */
    function registerValidators(address podOwner, bytes[] calldata validatorPubkeys) external;

    /**
     * @notice Deregisters validators from the UniFi AVS.
     * @param validatorPubkeys The BLS public keys of the validators to deregister.
     */
    function deregisterValidators(bytes[] calldata validatorPubkeys) external;

    /**
     * @notice Sets the commitment for an operator.
     * @param newCommitment The new commitment to set.
     */
    function setOperatorCommitment(OperatorCommitment calldata newCommitment) external;

    /**
     * @notice Updates the metadata URI for the AVS
     * @param _metadataURI is the metadata URI for the AVS
     */
    function updateAVSMetadataURI(string calldata _metadataURI) external;

    /**
     * @notice Creates a new operator set with specified strategies.
     * @param operatorSetId The ID for the new operator set.
     * @param strategies The strategies to add to the operator set.
     */
    function createOperatorSet(uint32 operatorSetId, IStrategy[] calldata strategies) external;

    /**
     * @notice Adds strategies to an operator set.
     * @param operatorSetId The ID of the operator set.
     * @param strategies The strategies to add.
     */
    function addStrategiesToOperatorSet(uint32 operatorSetId, IStrategy[] calldata strategies) external;

    /**
     * @notice Removes strategies from an operator set.
     * /**
     * @notice Removes strategies from an operator set.
     * @param operatorSetId The ID of the operator set.
     * @param strategies The strategies to remove.
     */
    function removeStrategiesFromOperatorSet(uint32 operatorSetId, IStrategy[] calldata strategies) external;

    /**
     * @notice Retrieves the current operator set ID.
     * @return The current operator set ID.
     */
    function getCurrentOperatorSetId() external view returns (uint32);

    /**
     * @notice Add or remove a strategy address from the allowlist of restaking strategies
     * @param strategy The address of the strategy to add or remove
     * @param allowed Whether the strategy should be allowed (true) or disallowed (false)
     * @dev Restricted to the DAO
     */
    function setAllowlistRestakingStrategy(address strategy, bool allowed) external;

    /**
     * @notice Retrieves the commitment delay.
     * @return The commitment delay.
     */
    function getCommitmentDelay() external view returns (uint64);

    /**
     * @notice Retrieves information about a specific operator.
     * @param operator The address of the operator.
     * @return OperatorDataExtended struct containing information about the operator.
     */
    function getOperator(address operator) external view returns (OperatorDataExtended memory);

    /**
     * @notice Retrieves information about a validator using its BLS public key hash.
     * @param validatorPubkey The BLS public key of the validator.
     * @return ValidatorDataExtended struct containing information about the validator.
     */
    function getValidator(bytes calldata validatorPubkey) external view returns (ValidatorDataExtended memory);

    /**
     * @notice Retrieves information about a validator using its validator index.
     * @param validatorIndex The index of the validator.
     * @return ValidatorDataExtended struct containing information about the validator.
     */
    function getValidatorByIndex(uint256 validatorIndex) external view returns (ValidatorDataExtended memory);

    /**
     * @notice Retrieves information about multiple validators.
     * @param validatorPubkeys The BLS public keys of the validators.
     * @return An array of ValidatorDataExtended structs containing information about the validators.
     */
    function getValidators(bytes[] calldata validatorPubkeys) external view returns (ValidatorDataExtended[] memory);

    /**
     * @notice Checks if a validator is registered for a specific chain ID.
     * @param validatorPubkey The BLS public key of the validator.
     * @param chainId The chain ID to check.
     * @return bool True if the validator is registered for the given chain ID, false otherwise.
     */
    function isValidatorInChainId(bytes calldata validatorPubkey, uint256 chainId) external view returns (bool);

    /**
     * @notice Returns the list of strategies that the operator has potentially restaked on the AVS
     * @param operator The address of the operator to get restaked strategies for
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on whether the operator has shares for a strategy in a quorum or uniqueness
     *      of each element in the returned array. The off-chain service should do that validation separately
     */
    function getOperatorRestakedStrategies(address operator) external view returns (address[] memory);

    /**
     * @notice Returns the list of strategies that the AVS supports for restaking
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on uniqueness of each element in the returned array.
     *      The off-chain service should do that validation separately
     */
    function getRestakeableStrategies() external view returns (address[] memory);

    /**
     * @notice Submits EigenLayer rewards for operators.
     * @param submissions The array of rewards submissions.
     */
    function submitOperatorRewards(IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions)
        external;

    /**
     * @notice Sets the claimer for the AVS to get excess rewards back.
     * @param claimer The address of the claimer.
     */
    function setClaimerFor(address claimer) external;

    /**
     * @notice Sets the current operator set ID.
     * @param operatorSetId The ID of the operator set.
     */
    function setCurrentOperatorSetId(uint32 operatorSetId) external;
}
