// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BN254 } from "../library/BN254.sol";

/**
 * @title IUnifiRewardsDistributor
 * @notice Interface for the UnifiRewardsDistributor contract
 */
interface IUnifiRewardsDistributor {
    /**
     * @notice Struct used when registering a new public key
     * @param pubkeyRegistrationSignature is the registration message signed by the private key of the validator
     * @param pubkeyG1 is the corresponding G1 public key of the validator
     * @param pubkeyG2 is the corresponding G2 public key of the validator
     */
    struct PubkeyRegistrationParams {
        BN254.G1Point pubkeyRegistrationSignature;
        BN254.G1Point pubkeyG1;
        BN254.G2Point pubkeyG2;
    }

    /**
     * @notice Registers the `claimer`'s address for the validator's BLS public key
     * @param claimer The address of the claimer to register.
     * @param params contains the G1 & G2 public keys of the validator, and a signature proving their ownership
     */
    function registerClaimer(address claimer, PubkeyRegistrationParams calldata params) external;
}
