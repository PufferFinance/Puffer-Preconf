// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IUniFiAVSDisputeManager
 * @dev Interface for the UniFiAVSDisputeManager contract.
 */
interface IUniFiAVSDisputeManager {
    /**
     * @dev Emitted when an operator is slashed.
     * @param operator The address of the operator that was slashed.
     * @param validatorIds The array of validator IDs associated with the operator.
     * @param slashingBeneficiary The address that benefits from the slashing.
     */
    event OperatorSlashed(address indexed operator, bytes32[] validatorIds, address slashingBeneficiary);

    /**
     * @dev Slashes an operator by storing their invalid validators and specifying a beneficiary.
     * @param operator The address of the operator to be slashed.
     * @param validators An array of validators associated with the operator.
     * @param slashingBeneficiary The address that will benefit from the slashing.
     */
    function slashOperator(address operator, bytes32[] calldata validators, address slashingBeneficiary) external;

    /**
     * @dev Checks if an operator has been slashed.
     * @param operator The address of the operator to check.
     * @return True if the operator has been slashed, false otherwise.
     */
    function isOperatorSlashed(address operator) external view returns (bool);
}
