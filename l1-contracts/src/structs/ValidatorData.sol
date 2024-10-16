// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "eigenlayer/interfaces/IEigenPod.sol";
import { BN254 } from "eigenlayer-middleware/libraries/BN254.sol";

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
    /// @notice The block number after which the validator is registered.
    uint64 registeredAfter;
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
    IEigenPod.VALIDATOR_STATUS eigenPodStatus;
    /// @notice The delegate key currently associated with the validator's operator.
    bytes delegateKey;
    /// @notice Bitmap of chain IDs the validator's operator is committed to.
    uint256 chainIDBitMap;
    /// @notice Indicates whether the validator's EigenPod is currently delegated to the operator.
    bool backedByEigenPodStake;
    /// @notice Indicates whether the validator is currently registered (current block < registeredUntil).
    bool registered;
}

/**
 * @title ValidatorRegistrationData
 * @notice Struct to store registration-related data for a validator.
 */
struct ValidatorRegistrationData {
    BN254.G1Point registrationSignature;
    BN254.G1Point pubkeyG1;
    BN254.G2Point pubkeyG2;
    bytes32 salt;
    uint64 registeredAt;
    uint64 expiry;
}

/**
 * @title ValidatorRegistrationParams
 * @notice Struct to store parameters for validator registration.
 */
struct ValidatorRegistrationParams {
    bytes32 blsPubKeyHash;
    BN254.G1Point registrationSignature;
    BN254.G1Point pubkeyG1;
    BN254.G2Point pubkeyG2;
    uint64 index;
    uint256 expiry;
    bytes32 salt;
}

/**
 * @title InvalidValidator
 * @notice Struct to store information about a slashed validator.
 */
struct InvalidValidator {
    address slashingBeneficiary;
    bytes32 blsPubKeyHash;
}
