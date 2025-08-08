// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessManagedUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { ISignatureUtilsMixin } from "eigenlayer/interfaces/ISignatureUtilsMixin.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IAllocationManager, IAllocationManagerTypes } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IAVSRegistrar } from "eigenlayer/interfaces/IAVSRegistrar.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IEigenPod, IEigenPodTypes } from "eigenlayer/interfaces/IEigenPod.sol";
import { IUniFiAVSManager } from "./interfaces/IUniFiAVSManager.sol";
import { UniFiAVSManagerStorage } from "./UniFiAVSManagerStorage.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { OperatorSet } from "eigenlayer/libraries/OperatorSetLib.sol";

contract UniFiAVSManager is IUniFiAVSManager, UniFiAVSManagerStorage, UUPSUpgradeable, AccessManagedUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using SafeERC20 for IERC20;

    address public constant BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

    /**
     * @notice The EigenPodManager
     */
    IEigenPodManager public immutable override EIGEN_POD_MANAGER;
    /**
     * @notice The EigenDelegationManager
     */
    IDelegationManager public immutable override EIGEN_DELEGATION_MANAGER;
    /**
     * @notice The RewardsCoordinator contract
     */
    IRewardsCoordinator public immutable EIGEN_REWARDS_COORDINATOR;
    /**
     * @notice The AllocationManager contract
     */
    IAllocationManager public immutable override ALLOCATION_MANAGER;

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
     * @dev Internal function to check if operator is registered to any operator sets
     * @param operator The address of the operator
     */
    function _isOperatorRegistered(address operator) internal view returns (bool) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        if ($.currentOperatorSetId == 0) {
            return false;
        }
        if ($.operators[operator].deregisteredBlockNumber != 0) {
            return false;
        }
        return ALLOCATION_MANAGER.isMemberOfOperatorSet(
            operator, OperatorSet({ avs: address(this), id: $.currentOperatorSetId })
        );
    }

    /**
     * @dev Internal function to check if a validator is registered
     * @param validatorPubkey The BLS public key of the validator
     */
    function _isValidatorRegistered(bytes memory validatorPubkey) internal view returns (bool) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.validators[validatorPubkey].index != 0 && block.number < $.validators[validatorPubkey].registeredUntil
            && _isOperatorRegistered($.validators[validatorPubkey].operator);
    }

    /**
     * @dev Modifier to check if the operator is registered in the AVS
     * @param operator The address of the operator
     */
    modifier registeredOperator(address operator) {
        if (!_isOperatorRegistered(operator)) {
            revert OperatorNotRegistered();
        }
        _;
    }

    constructor(
        IEigenPodManager eigenPodManagerAddress,
        IDelegationManager eigenDelegationManagerAddress,
        IAllocationManager allocationManagerAddress,
        IRewardsCoordinator rewardsCoordinatorAddress
    ) {
        if (address(eigenPodManagerAddress) == address(0)) {
            revert InvalidEigenPodManagerAddress();
        }
        if (address(eigenDelegationManagerAddress) == address(0)) {
            revert InvalidEigenDelegationManagerAddress();
        }
        if (address(allocationManagerAddress) == address(0)) {
            revert InvalidAllocationManagerAddress();
        }
        if (address(rewardsCoordinatorAddress) == address(0)) {
            revert InvalidRewardsCoordinatorAddress();
        }
        EIGEN_POD_MANAGER = eigenPodManagerAddress;
        EIGEN_DELEGATION_MANAGER = eigenDelegationManagerAddress;
        ALLOCATION_MANAGER = allocationManagerAddress;
        EIGEN_REWARDS_COORDINATOR = rewardsCoordinatorAddress;
        _disableInitializers();
    }

    function initialize(address, uint64) public initializer {
        // This is a no-op for the initial version of the contract
    }

    function initializeV2(address accessManager, uint64 initialCommitmentDelay) public reinitializer(2) {
        __AccessManaged_init(accessManager);
        __Context_init();
        __UUPSUpgradeable_init();

        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        $.commitmentDelay = initialCommitmentDelay;
    }

    // EXTERNAL FUNCTIONS

    /// @inheritdoc IAVSRegistrar
    function registerOperator(address operator, address avs, uint32[] calldata operatorSetIds, bytes calldata data)
        external
        override
    {
        if (msg.sender != address(ALLOCATION_MANAGER)) {
            revert OnlyAllocationManager();
        }
        if (avs != address(this)) {
            revert InvalidAVSAddress();
        }

        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        if (operatorSetIds.length != 1 || operatorSetIds[0] != $.currentOperatorSetId) {
            revert InvalidOperatorSetsProvided();
        }

        $.operators[operator].deregisteredBlockNumber = 0;

        // Decode optional commitment data if provided
        OperatorCommitment memory initialCommitment;
        if (data.length > 0) {
            initialCommitment = abi.decode(data, (OperatorCommitment));
            $.operators[operator].commitment = initialCommitment;
            $.operators[operator].commitmentValidAfter = 0;
            emit OperatorRegisteredWithCommitment(operator, operatorSetIds, initialCommitment);
        } else {
            emit OperatorRegistered(operator, operatorSetIds);
        }
    }

    /// @inheritdoc IAVSRegistrar
    function deregisterOperator(address operator, address avs, uint32[] calldata operatorSetIds) external override {
        if (msg.sender != address(ALLOCATION_MANAGER)) {
            revert OnlyAllocationManager();
        }
        if (avs != address(this)) {
            revert InvalidAVSAddress();
        }
        
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        
        if (operatorSetIds.length != 1 || operatorSetIds[0] != $.currentOperatorSetId) {
            revert InvalidOperatorSetsProvided();
        }

        OperatorData storage operatorData = $.operators[operator];
        operatorData.deregisteredBlockNumber = uint64(block.number);
        delete operatorData.commitment;
        delete operatorData.pendingCommitment;
        delete operatorData.validatorCount;
        delete operatorData.commitmentValidAfter;

        emit OperatorDeregistered(operator, operatorSetIds);
    }

    /// @inheritdoc IAVSRegistrar
    function supportsAVS(address avs) external view override returns (bool) {
        return avs == address(this);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerValidators(address podOwner, bytes[] calldata validatorPubkeys)
        external
        podIsDelegatedToMsgSender(podOwner)
        registeredOperator(msg.sender)
        restricted
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        bytes memory delegateKey = _getActiveCommitment($.operators[msg.sender]).delegateKey;

        if (delegateKey.length == 0) {
            revert DelegateKeyNotSet();
        }

        IEigenPod eigenPod = EIGEN_POD_MANAGER.getPod(podOwner);

        uint256 newValidatorCount = validatorPubkeys.length;

        for (uint256 i = 0; i < newValidatorCount; i++) {
            bytes memory validatorPubkey = validatorPubkeys[i];
            IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyToInfo(validatorPubkey);

            if (validatorInfo.status != IEigenPodTypes.VALIDATOR_STATUS.ACTIVE) {
                revert ValidatorNotActive();
            }

            if (_isValidatorRegistered(validatorPubkey)) {
                revert ValidatorAlreadyRegistered();
            }

            // Store the validator record
            $.validators[validatorPubkey] = ValidatorData({
                eigenPod: address(eigenPod),
                index: validatorInfo.validatorIndex,
                operator: msg.sender,
                registeredUntil: type(uint64).max
            });

            // Also track the mapping from index -> BLS key
            $.validatorIndexes[validatorInfo.validatorIndex] = validatorPubkey;

            emit ValidatorRegistered({
                podOwner: podOwner,
                operator: msg.sender,
                delegateKey: delegateKey,
                validatorPubkey: validatorPubkey,
                validatorIndex: validatorInfo.validatorIndex
            });
        }

        OperatorData storage operator = $.operators[msg.sender];
        operator.validatorCount += uint128(newValidatorCount);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function deregisterValidators(bytes[] calldata validatorPubkeys) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        uint256 validatorCount = validatorPubkeys.length;

        for (uint256 i = 0; i < validatorCount; i++) {
            bytes memory validatorPubkey = validatorPubkeys[i];
            ValidatorData storage validator = $.validators[validatorPubkey];

            address operator = validator.operator;

            if (operator != msg.sender) {
                revert NotValidatorOperator();
            }

            if (!_isValidatorRegistered(validatorPubkey)) {
                revert ValidatorNotRegistered();
            }

            // Mark the validator as deregistered
            validator.registeredUntil = uint64(block.number);

            emit ValidatorDeregistered({ operator: operator, validatorPubkey: validatorPubkey });
        }

        $.operators[msg.sender].validatorCount -= uint128(validatorCount);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function setOperatorCommitment(OperatorCommitment calldata newCommitment)
        external
        registeredOperator(msg.sender)
        restricted
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operator = $.operators[msg.sender];

        if (operator.commitmentValidAfter != 0 && block.number >= operator.commitmentValidAfter) {
            operator.commitment = operator.pendingCommitment;
        }

        operator.pendingCommitment = newCommitment;
        operator.commitmentValidAfter = uint64(block.number) + $.commitmentDelay;

        emit OperatorCommitmentChangeInitiated({
            operator: msg.sender,
            oldCommitment: operator.commitment,
            newCommitment: newCommitment,
            validAfter: operator.commitmentValidAfter
        });
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function updateAVSMetadataURI(string calldata _metadataURI) external restricted {
        ALLOCATION_MANAGER.updateAVSMetadataURI(address(this), _metadataURI);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function createOperatorSet(uint32 operatorSetId, IStrategy[] calldata strategies) external restricted {
        if (operatorSetId == 0) {
            revert InvalidOperatorSetId();
        }

        IStrategy[] memory istrategies = new IStrategy[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            istrategies[i] = IStrategy(strategies[i]);
        }

        IAllocationManagerTypes.CreateSetParams[] memory params = new IAllocationManagerTypes.CreateSetParams[](1);
        params[0] = IAllocationManagerTypes.CreateSetParams({ operatorSetId: operatorSetId, strategies: istrategies });

        ALLOCATION_MANAGER.createOperatorSets(address(this), params);
        emit OperatorSetCreated(operatorSetId);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function addStrategiesToOperatorSet(uint32 operatorSetId, IStrategy[] calldata strategies) external restricted {
        ALLOCATION_MANAGER.addStrategiesToOperatorSet(address(this), operatorSetId, strategies);
        emit StrategiesAddedToOperatorSet(operatorSetId, strategies);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function removeStrategiesFromOperatorSet(uint32 operatorSetId, IStrategy[] calldata strategies)
        external
        restricted
    {
        ALLOCATION_MANAGER.removeStrategiesFromOperatorSet(address(this), operatorSetId, strategies);
        emit StrategiesRemovedFromOperatorSet(operatorSetId, strategies);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the DAO
     */
    function setCurrentOperatorSetId(uint32 operatorSetId) external restricted {
        if (operatorSetId == 0) {
            revert InvalidOperatorSetId();
        }
        if (!ALLOCATION_MANAGER.isOperatorSet(OperatorSet({ avs: address(this), id: operatorSetId }))) {
            revert OperatorSetDoesNotExist();
        }
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        $.currentOperatorSetId = operatorSetId;
        emit CurrentOperatorSetIdSet(operatorSetId);
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

    /**
     * @inheritdoc IUniFiAVSManager
     * @dev Restricted to the OPERATIONS_MULTISIG
     */
    function submitOperatorRewards(IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions)
        external
        restricted
    {
        uint256 submissionsLength = submissions.length;
        for (uint256 i = 0; i < submissionsLength; i++) {
            IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission = submissions[i];
            uint256 totalRewards = 0;
            uint256 rewardsLength = submission.operatorRewards.length;
            for (uint256 j = 0; j < rewardsLength; j++) {
                totalRewards += submission.operatorRewards[j].amount;
            }
            IERC20(address(submission.token)).safeIncreaseAllowance(address(EIGEN_REWARDS_COORDINATOR), totalRewards);
        }
        EIGEN_REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(address(this), submissions);

        emit OperatorRewardsSubmitted();
    }

    function setClaimerFor(address claimer) external restricted {
        EIGEN_REWARDS_COORDINATOR.setClaimerFor(claimer);
    }

    function setCommitmentDelay(uint64 commitmentDelay) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        uint64 oldDelay = $.commitmentDelay;
        $.commitmentDelay = commitmentDelay;

        emit CommitmentDelaySet(oldDelay, commitmentDelay);
    }

    // GETTERS

    function getCurrentOperatorSetId() external view returns (uint32) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.currentOperatorSetId;
    }

    function getCommitmentDelay() external view returns (uint64) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.commitmentDelay;
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
    function getValidator(bytes calldata validatorPubkey) external view returns (ValidatorDataExtended memory) {
        return _getValidator(validatorPubkey);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getValidatorByIndex(uint256 validatorIndex) external view returns (ValidatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        bytes memory validatorPubkey = $.validatorIndexes[validatorIndex];
        return _getValidator(validatorPubkey);
    }

    /**
     * @inheritdoc IUniFiAVSManager
     */
    function getValidators(bytes[] calldata validatorPubkeys) external view returns (ValidatorDataExtended[] memory) {
        uint256 validatorPubkeysLength = validatorPubkeys.length;
        ValidatorDataExtended[] memory validators = new ValidatorDataExtended[](validatorPubkeysLength);
        for (uint256 i = 0; i < validatorPubkeysLength; i++) {
            validators[i] = _getValidator(validatorPubkeys[i]);
        }
        return validators;
    }

    /**
     * @notice Checks if a given validator is committed to a particular chain ID,
     * by looking up its operator's active chain commitments.
     */
    function isValidatorInChainId(bytes calldata validatorPubkey, uint256 chainId) external view returns (bool) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        ValidatorData storage validator = $.validators[validatorPubkey];

        // If the validator is never registered or is already deregistered, return false
        if (!_isValidatorRegistered(validatorPubkey)) {
            return false;
        }

        // Check if the operator has the chainId in its active commitment
        OperatorData storage operatorData = $.operators[validator.operator];
        OperatorCommitment memory activeCommitment = _getActiveCommitment(operatorData);

        for (uint256 i = 0; i < activeCommitment.chainIds.length; i++) {
            if (activeCommitment.chainIds[i] == chainId) {
                return true;
            }
        }
        return false;
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
                    restakedStrategies[restakedCount++] = address(strategies[i]);
                }
            }

            // Resize the array to the actual number of restaked strategies
            assembly {
                if lt(restakedCount, allowlistedCount) { mstore(restakedStrategies, restakedCount) }
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

    // INTERNAL FUNCTIONS

    function _getOperator(address operator) internal view returns (OperatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operatorData = $.operators[operator];

        OperatorCommitment memory activeCommitment = _getActiveCommitment(operatorData);

        return OperatorDataExtended({
            validatorCount: operatorData.validatorCount,
            commitment: activeCommitment,
            pendingCommitment: operatorData.pendingCommitment,
            isRegistered: _isOperatorRegistered(operator),
            commitmentValidAfter: operatorData.commitmentValidAfter
        });
    }

    function _getValidator(bytes memory validatorPubkey)
        internal
        view
        returns (ValidatorDataExtended memory validator)
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        ValidatorData memory validatorData = $.validators[validatorPubkey];

        if (validatorData.index != 0) {
            IEigenPod eigenPod = IEigenPod(validatorData.eigenPod);
            IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyToInfo(validatorPubkey);

            bool backedByStake = EIGEN_DELEGATION_MANAGER.delegatedTo(eigenPod.podOwner()) == validatorData.operator;

            OperatorData storage operator = $.operators[validatorData.operator];
            OperatorCommitment memory activeCommitment = _getActiveCommitment(operator);

            return ValidatorDataExtended({
                operator: validatorData.operator,
                eigenPod: validatorData.eigenPod,
                validatorIndex: validatorInfo.validatorIndex,
                status: validatorInfo.status,
                delegateKey: activeCommitment.delegateKey,
                chainIds: activeCommitment.chainIds,
                backedByStake: backedByStake,
                registered: _isValidatorRegistered(validatorPubkey)
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

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
