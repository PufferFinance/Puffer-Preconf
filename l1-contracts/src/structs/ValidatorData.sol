// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

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
}
