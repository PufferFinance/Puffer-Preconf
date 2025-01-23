// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { IAVSDirectoryExtended } from "../interfaces/EigenLayer/IAVSDirectoryExtended.sol";
import "../structs/ValidatorData.sol";
import "../structs/OperatorData.sol";

/**
 * @title IUniFiAVSManager
 * @notice Interface for the UniFiAVSManager contract, which manages operators and validators in the UniFi AVS.
 * @dev This interface defines the main functions and events for operator and validator management.
 */
interface IUniFiAVSManager {
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

    /// @notice Thrown when attempting to register an operator that is already registered
    error OperatorAlreadyRegistered();

    /// @notice Thrown when a non-operator attempts to deregister a validator
    error NotValidatorOperator();

    /// @notice Thrown when attempting to register a validator that is already registered
    error ValidatorAlreadyRegistered();

    /// @notice Thrown when an operator's delegate key is not set
    error DelegateKeyNotSet();

    /// @notice Thrown when a validator cannot be found
    error ValidatorNotFound();

    /// @notice Thrown when an unauthorized action is attempted
    error Unauthorized();

    /// @notice Thrown when trying to update an operator commitment before the change delay has passed
    error CommitmentChangeNotReady();

    /// @notice Thrown when an index is out of bounds
    error IndexOutOfBounds();

    /// @notice Thrown when attempting to deregister a validator that is already deregistered
    error ValidatorAlreadyDeregistered();

    /// @notice Thrown when a restaking strategy allowlist update fails
    error RestakingStrategyAllowlistUpdateFailed();

    /**
     * @notice Emitted when a new operator is registered in the UniFi AVS.
     * @param operator The address of the registered operator.
     */
    event OperatorRegistered(address indexed operator);

    /**
     * @notice Emitted when a new operator is registered in the UniFi AVS with a commitment.
     * @param operator The address of the registered operator.
     * @param commitment The commitment set for the operator.
     */
    event OperatorRegisteredWithCommitment(address indexed operator, OperatorCommitment commitment);

    /**
     * @notice Emitted when a new validator is registered in the UniFi AVS .
     * @param podOwner The address of the validator's EigenPod owner.
     * @param delegateKey The delegate public key for the validator.
     * @param blsPubKeyHash The BLS public key hash of the validator.
     * @param validatorIndex The beacon chain validator index.
     */
    event ValidatorRegistered(
        address indexed podOwner,
        address indexed operator,
        bytes delegateKey,
        bytes32 blsPubKeyHash,
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
     */
    event OperatorDeregistered(address indexed operator);

    /**
     * @notice Emitted when a validator is deregistered from the UniFi AVS.
     * @param operator The address of the operator managing the validator.
     * @param blsPubKeyHash The BLS public key hash of the deregistered validator.
     */
    event ValidatorDeregistered(address indexed operator, bytes32 blsPubKeyHash);

    /**
     * @notice Emitted when an operator's commitment is set or updated.
     * @param operator The address of the operator.
     * @param oldCommitment The previous commitment for the operator.
     * @param newCommitment The new commitment for the operator.
     */
    event OperatorCommitmentSet(
        address indexed operator, OperatorCommitment oldCommitment, OperatorCommitment newCommitment
    );

    event OperatorCommitmentChangeInitiated(
        address indexed operator, OperatorCommitment oldCommitment, OperatorCommitment newCommitment, uint128 validAfter
    );

    /**
     * @notice Emitted when the deregistration delay is updated.
     * @param oldDelay The previous deregistration delay value.
     * @param newDelay The new deregistration delay value.
     */
    event DeregistrationDelaySet(uint64 oldDelay, uint64 newDelay);

    /**
     * @notice Emitted when a chain ID is set for a specific index.
     * @param index The index in the bitmap.
     * @param chainID The chain ID set for the given index.
     */
    event ChainIDSet(uint8 index, uint256 chainID);

    /**
     * @notice Emitted when a restaking strategy is added or removed from the allowlist.
     * @param strategy The address of the strategy.
     * @param allowed Whether the strategy is allowed (true) or disallowed (false).
     */
    event RestakingStrategyAllowlistUpdated(address indexed strategy, bool allowed);

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
     * @notice Returns the AVSDirectoryExtended contract.
     * @return IAVSDirectoryExtended The AVSDirectoryExtended contract.
     */
    function AVS_DIRECTORY() external view returns (IAVSDirectoryExtended);

    /**
     * @notice Registers a new operator in the UniFi AVS.
     * @param operatorSignature The signature and associated data for operator registration.
     */
    function registerOperator(ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) external;

    /**
     * @notice Registers a new operator in the UniFi AVS with a commitment.
     * @param operatorSignature The signature and associated data for operator registration.
     * @param initialCommitment The initial commitment for the operator.
     */
    function registerOperatorWithCommitment(
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature,
        OperatorCommitment memory initialCommitment
    ) external;

    /**
     * @notice Registers validators for a given pod owner.
     * @param podOwner The address of the pod owner.
     * @param blsPubKeyHashes The BLS public key hashes of the validators to register.
     */
    function registerValidators(address podOwner, bytes32[] calldata blsPubKeyHashes) external;

    /**
     * @notice Deregisters validators from the UniFi AVS.
     * @param blsPubKeyHashes The BLS public key hashes of the validators to deregister.
     */
    function deregisterValidators(bytes32[] calldata blsPubKeyHashes) external;

    /**
     * @notice Starts the process of deregistering an operator from the UniFi AVS.
     */
    function startDeregisterOperator() external;

    /**
     * @notice Finishes the process of deregistering an operator from the UniFi AVS.
     */
    function finishDeregisterOperator() external;
    /**
     * @notice Sets the commitment for an operator.
     * @param newCommitment The new commitment to set.
     */
    function setOperatorCommitment(OperatorCommitment memory newCommitment) external;

    /**
     * @notice Updates the operator's commitment after the delay period.
     */
    function updateOperatorCommitment() external;

    /**
     * @notice Updates the metadata URI for the AVS
     * @param _metadataURI is the metadata URI for the AVS
     */
    function updateAVSMetadataURI(string memory _metadataURI) external;

    /**
     * @notice Sets a new deregistration delay for operators.
     * @param newDelay The new deregistration delay in seconds.
     * @dev Restricted to the DAO
     */
    function setDeregistrationDelay(uint64 newDelay) external;

    /**
     * @notice Sets the chain ID for a specific index in the bitmap.
     * @param index The index in the bitmap to set.
     * @param chainID The chain ID to set for the given index.
     * @dev Restricted to the DAO
     */
    function setChainID(uint8 index, uint256 chainID) external;

    /**
     * @notice Add or remove a strategy address from the allowlist of restaking strategies
     * @param strategy The address of the strategy to add or remove
     * @param allowed Whether the strategy should be allowed (true) or disallowed (false)
     * @dev Restricted to the DAO
     */
    function setAllowlistRestakingStrategy(address strategy, bool allowed) external;

    /**
     * @notice Retrieves information about a specific operator.
     * @param operator The address of the operator.
     * @return OperatorDataExtended struct containing information about the operator.
     */
    function getOperator(address operator) external view returns (OperatorDataExtended memory);

    /**
     * @notice Retrieves information about a validator using its BLS public key hash.
     * @param blsPubKeyHash The BLS public key hash of the validator.
     * @return ValidatorDataExtended struct containing information about the validator.
     */
    function getValidator(bytes32 blsPubKeyHash) external view returns (ValidatorDataExtended memory);

    /**
     * @notice Retrieves information about a validator using its validator index.
     * @param validatorIndex The index of the validator.
     * @return ValidatorDataExtended struct containing information about the validator.
     */
    function getValidator(uint256 validatorIndex) external view returns (ValidatorDataExtended memory);

    /**
     * @notice Retrieves information about multiple validators.
     * @param blsPubKeyHashes The BLS public key hashes of the validators.
     * @return An array of ValidatorDataExtended structs containing information about the validators.
     */
    function getValidators(bytes32[] calldata blsPubKeyHashes) external view returns (ValidatorDataExtended[] memory);

    /**
     * @notice Checks if a validator is registered for a specific chain ID.
     * @param blsPubKeyHash The BLS public key hash of the validator.
     * @param chainId The chain ID to check.
     * @return bool True if the validator is registered for the given chain ID, false otherwise.
     */
    function isValidatorInChainId(bytes32 blsPubKeyHash, uint256 chainId) external view returns (bool);

    /**
     * @notice Retrieves the current deregistration delay for operators.
     * @return The current deregistration delay in seconds.
     */
    function getDeregistrationDelay() external view returns (uint64);

    /**
     * @notice Converts a bitmap to an array of chain IDs.
     * @param bitmap The bitmap to convert.
     * @return An array of chain IDs represented by the bitmap.
     */
    function bitmapToChainIDs(uint256 bitmap) external view returns (uint256[] memory);

    /**
     * @notice Retrieves the chain ID for a specific index.
     * @param index The index to query.
     * @return The chain ID associated with the given index.
     */
    function getChainID(uint8 index) external view returns (uint256);

    /**
     * @notice Gets the bitmap index for a given chain ID.
     * @param chainID The chain ID to query.
     * @return The bitmap index associated with the given chain ID.
     */
    function getBitmapIndex(uint256 chainID) external view returns (uint8);

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

    /// @notice Returns the EigenLayer AVSDirectory contract.
    function avsDirectory() external view returns (address);
}
