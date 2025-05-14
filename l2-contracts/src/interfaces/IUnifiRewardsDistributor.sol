// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "../library/BLS.sol";

/**
 * @title IUnifiRewardsDistributor
 * @notice Interface for the UnifiRewardsDistributor contract
 */
interface IUnifiRewardsDistributor {
    /// @notice Thrown when the input is invalid
    error InvalidInput();
    /// @notice Thrown when a zero pubkey is registered
    error CannotRegisterZeroPubKey();
    /// @notice Thrown when a bad BLS signature is provided
    error BadBLSSignature();
    /// @notice Thrown when a claimer is not set for a validator
    error ClaimerNotSet();
    /// @notice Thrown when an invalid proof is provided
    error InvalidProof();
    /// @notice Thrown when a validator has no rewards to claim
    error NothingToClaim();
    /// @notice Thrown when a zero merkle root is set
    error MerkleRootCannotBeZero();
    /// @notice Thrown when a pending merkle root is not set
    error NoPendingMerkleRoot();

    /// @notice Emitted when a claimer is set for a validator
    event ClaimerSet(bytes32 indexed blsPubkeyHash, address indexed claimer);
    /// @notice Emitted when the merkle root is set for the new cumulative distribution
    event MerkleRootSet(bytes32 indexed newMerkleRoot, uint256 activationTimestamp);
    /// @notice Emitted when rewards are claimed for a validator
    event RewardsClaimed(bytes32 indexed blsPubkeyHash, uint256 indexed amount);
    /// @notice Emitted when the pending merkle root is cancelled
    event PendingMerkleRootCancelled(bytes32 indexed merkleRoot);

    /**
     * @notice Struct used when registering a new public key
     * @param pubkeyRegistrationSignature is the registration message signed by the private key of the validator
     * @param pubkeyG1 is the corresponding G1 public key of the validator
     * @param pubkeyG2 is the corresponding G2 public key of the validator
     */
    struct PubkeyRegistrationParams {
        BLS.G2Point signature;
        BLS.G1Point publicKey;
    }

    /**
     * @notice Registers the `claimer`'s address for the validator's BLS public keys
     * @param claimer The address of the claimer to register.
     * @param params is an array of structs containing the G1 & G2 public keys of the validator, and a signature proving their ownership
     */
    function registerClaimer(address claimer, PubkeyRegistrationParams[] calldata params) external;
}
