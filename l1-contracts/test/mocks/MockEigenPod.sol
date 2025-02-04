// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IEigenPod, IEigenPodManager, IERC20, BeaconChainProofs } from "eigenlayer/interfaces/IEigenPod.sol";

contract MockEigenPod is IEigenPod {
    mapping(bytes32 validatorPubkeyHash => ValidatorInfo validatorInfo) public validators;
    mapping(bytes32 validatorPubkeyHash => mapping(uint64 slot => bool proven)) public provenWithdrawals;
    address public owner;

    function setValidator(bytes32 pubkeyHash, ValidatorInfo calldata validator) external {
        validators[pubkeyHash].validatorIndex = validator.validatorIndex;
        validators[pubkeyHash].restakedBalanceGwei = validator.restakedBalanceGwei;
        validators[pubkeyHash].lastCheckpointedAt = validator.lastCheckpointedAt;
        validators[pubkeyHash].status = validator.status;
    }

    function setValidatorStatus(bytes32 pubkeyHash, VALIDATOR_STATUS status) external {
        validators[pubkeyHash].validatorIndex =
            validators[pubkeyHash].validatorIndex == 0 ? uint64(uint256(pubkeyHash)) : validators[pubkeyHash].validatorIndex;
        validators[pubkeyHash].status = status;
    }

    function validatorStatus(bytes32 pubkeyHash) external view returns (VALIDATOR_STATUS) {
        return validators[pubkeyHash].status;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    // Implement required functions with minimal functionality
    function MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR() external pure returns (uint64) {
        return 0;
    }

    function activateRestaking() external { }

    function eigenPodManager() external pure returns (IEigenPodManager) {
        return IEigenPodManager(address(0));
    }

    function hasRestaked() external pure returns (bool) {
        return false;
    }

    function initialize(address) external { }

    function mostRecentWithdrawalTimestamp() external pure returns (uint64) {
        return 0;
    }

    function nonBeaconChainETHBalanceWei() external pure returns (uint256) {
        return 0;
    }

    function podOwner() external view returns (address) {
        return owner;
    }

    function provenWithdrawal(bytes32 validatorPubkeyHash, uint64 slot) external view returns (bool) {
        return provenWithdrawals[validatorPubkeyHash][slot];
    }

    function recoverTokens(IERC20[] memory, uint256[] memory, address) external { }
    function stake(bytes calldata, bytes calldata, bytes32) external payable { }

    function validatorPubkeyHashToInfo(bytes32 pubkeyHash) external view returns (ValidatorInfo memory) {
        return validators[pubkeyHash];
    }

    function validatorPubkeyToInfo(bytes calldata) external pure returns (ValidatorInfo memory) {
        return ValidatorInfo(1, 0, 0, VALIDATOR_STATUS.INACTIVE);
    }

    function validatorStatus(bytes calldata) external pure returns (VALIDATOR_STATUS) {
        return VALIDATOR_STATUS.INACTIVE;
    }

    function withdrawBeforeRestaking() external { }
    function withdrawNonBeaconChainETHBalanceWei(address, uint256) external { }
    function withdrawRestakedBeaconChainETH(address, uint256) external { }

    function withdrawableRestakedExecutionLayerGwei() external pure returns (uint64) {
        return 0;
    }

    function verifyBalanceUpdates(
        uint64,
        uint40[] calldata,
        BeaconChainProofs.StateRootProof calldata,
        bytes[] calldata,
        bytes32[][] calldata
    ) external { }

    function verifyWithdrawalCredentials(
        uint64,
        BeaconChainProofs.StateRootProof calldata,
        uint40[] calldata,
        bytes[] calldata,
        bytes32[][] calldata
    ) external { }

    // Add a function to set proven withdrawals for testing
    function setProvenWithdrawal(bytes32 validatorPubkeyHash, uint64 slot, bool proven) external {
        provenWithdrawals[validatorPubkeyHash][slot] = proven;
    }

    /// @notice Number of validators with proven withdrawal credentials, who do not have proven full withdrawals
    function activeValidatorCount() external view returns (uint256) {}

    function checkpointBalanceExitedGwei(uint64) external view returns (uint64) {}

    /// @notice The timestamp of the currently-active checkpoint. Will be 0 if there is not active checkpoint
    function currentCheckpointTimestamp() external view returns (uint64) {}

    /// @notice Returns the currently-active checkpoint
    function currentCheckpoint() external view returns (Checkpoint memory) {}

    /// @notice Query the 4788 oracle to get the parent block root of the slot with the given `timestamp`
    /// @param timestamp of the block for which the parent block root will be returned. MUST correspond
    /// to an existing slot within the last 24 hours. If the slot at `timestamp` was skipped, this method
    /// will revert.
    function getParentBlockRoot(uint64 timestamp) external view returns (bytes32) {}

    /// @notice The timestamp of the last checkpoint finalized
    function lastCheckpointTimestamp() external view returns (uint64) {}

    function setProofSubmitter(address newProofSubmitter) external {}

    function proofSubmitter() external view returns (address) {}

    function startCheckpoint(bool revertIfNoBalance) external {}

    function verifyCheckpointProofs(
        BeaconChainProofs.BalanceContainerProof calldata balanceContainerProof,
        BeaconChainProofs.BalanceProof[] calldata proofs
    ) external {}

    function verifyStaleBalance(
        uint64 beaconTimestamp,
        BeaconChainProofs.StateRootProof calldata stateRootProof,
        BeaconChainProofs.ValidatorProof calldata proof
    ) external {}
}
