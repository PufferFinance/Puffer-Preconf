// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IUnifiRewardsDistributor } from "./interfaces/IUnifiRewardsDistributor.sol";

import { BLS } from "./library/BLS.sol";
import { BN254 } from "./library/BN254.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract UnifiRewardsDistributor is IUnifiRewardsDistributor, EIP712, Ownable2Step {
    using Address for address payable;
    using BN254 for BN254.G1Point;

    /// @dev The delay for the Merkle root to be set
    uint256 public constant MERKLE_ROOT_DELAY = 1 days;
    // EIP-712 type definitions
    bytes32 public constant CLAIM_TYPEHASH = keccak256("SetClaimer(bytes32 blsPubkeyHash,address claimer)");
    string public constant DOMAIN_NAME = "UnifiRewardsDistributor";
    string public constant DOMAIN_VERSION = "1";

    /// @dev the hash of the zero pubkey aka BN254.G1Point(0,0)
    bytes32 internal constant _ZERO_PK_HASH = hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";

    /// @dev the mapping of BLS pubkey hash to claimer address
    mapping(bytes32 blsPubkeyHash => address claimer) public validatorClaimer;
    /// @dev the mapping of BLS pubkey hash to claimed amount
    mapping(bytes32 blsPubkeyHash => uint256 claimedAmount) public validatorClaimedAmount;
    /// @dev The Merkle root of the latest cumulative distribution
    bytes32 public merkleRoot;
    /// @dev The pending Merkle root. This merkle root will become active after the delay
    bytes32 public pendingMerkleRoot;
    /// @dev The timestamp when the pending Merkle root will become active
    uint256 public pendingMerkleRootActivationTimestamp;

    constructor() EIP712(DOMAIN_NAME, DOMAIN_VERSION) Ownable(msg.sender) { }

    /**
     * @dev Returns the hash of the fully encoded EIP-712 message for the claim data
     * @param blsPubkeyHash The hash of the BLS public key
     * @param claimer The address that will be able to claim rewards
     * @return The typed data hash
     */
    function getClaimerTypedDataHash(bytes32 blsPubkeyHash, address claimer) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, blsPubkeyHash, claimer));
        return _hashTypedDataV4(structHash);
    }

    /**
     * @notice Claim the unclaimed rewards for multiple validators
     * They all must have the same claimer set.
     * @param blsPubkeyHashes The hashes of the BLS public keys
     * @param amounts The total cumulative earned amounts
     * @param proofs The proofs of the claims
     */
    function claimRewards(bytes32[] calldata blsPubkeyHashes, uint256[] calldata amounts, bytes32[][] calldata proofs)
        external
    {
        require(blsPubkeyHashes.length == amounts.length && amounts.length == proofs.length, InvalidInput());

        // Get the claimer for the first pubkey hash
        address claimer = validatorClaimer[blsPubkeyHashes[0]];
        require(claimer != address(0), ClaimerNotSet());

        uint256 totalAmountToClaim = 0;

        for (uint256 i = 0; i < blsPubkeyHashes.length; ++i) {
            // All proofs must have the same claimer
            require(claimer == validatorClaimer[blsPubkeyHashes[i]], InvalidInput());

            uint256 claimedSoFar = validatorClaimedAmount[blsPubkeyHashes[i]];
            uint256 amountToClaim = amounts[i] - claimedSoFar;
            require(amountToClaim > 0, NothingToClaim());

            // Update the claimed amount to the latest amount
            validatorClaimedAmount[blsPubkeyHashes[i]] = amounts[i];

            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(blsPubkeyHashes[i], amounts[i]))));
            require(MerkleProof.verifyCalldata(proofs[i], getMerkleRoot(), leaf), InvalidProof());

            // Emit the claim event for each validator
            emit RewardsClaimed(blsPubkeyHashes[i], amountToClaim);

            totalAmountToClaim += amountToClaim;
        }

        // Send the total amount to the claimer
        payable(claimer).sendValue(totalAmountToClaim);
    }

    /**
     * @notice Set the Merkle root of the latest cumulative distribution
     * @param newMerkleRoot The new Merkle root
     */
    function setNewMerkleRoot(bytes32 newMerkleRoot) external onlyOwner {
        require(newMerkleRoot != bytes32(0), MerkleRootCannotBeZero());
        pendingMerkleRoot = newMerkleRoot;
        uint256 activationTimestamp = block.timestamp + MERKLE_ROOT_DELAY;
        pendingMerkleRootActivationTimestamp = activationTimestamp;
        emit MerkleRootSet(newMerkleRoot, activationTimestamp);
    }

    /**
     * @notice Cancel the pending Merkle root
     */
    function cancelPendingMerkleRoot() external onlyOwner {
        bytes32 merkleRootToCancel = pendingMerkleRoot;
        pendingMerkleRoot = bytes32(0);
        pendingMerkleRootActivationTimestamp = 0;
        emit PendingMerkleRootCancelled(merkleRootToCancel);
    }

    /**
     * @notice Called by the RegistryCoordinator register an operator as the owner of a BLS public key.
     * @param claimer is the claimer for whom the key is being registered
     * @param params contains the G1 & G2 public keys of the claimer, and a signature proving their ownership
     */
    function registerClaimer(address claimer, PubkeyRegistrationParams calldata params) external {
        require(
            params.pubkeyRegistrationSignature.X != 0 && params.pubkeyRegistrationSignature.Y != 0, BadBLSSignature()
        );

        bytes32 pubkeyHash = BN254.hashG1Point(params.pubkeyG1);
        require(pubkeyHash != _ZERO_PK_HASH, CannotRegisterZeroPubKey());

        BN254.G1Point memory claimerMessageHash = getClaimerMessageHash(pubkeyHash, claimer);

        // gamma = h(sigma, P, P', H(m))
        uint256 gamma = uint256(
            keccak256(
                abi.encodePacked(
                    params.pubkeyG1.X,
                    params.pubkeyG1.Y,
                    params.pubkeyG2.X[0],
                    params.pubkeyG2.X[1],
                    params.pubkeyG2.Y[0],
                    params.pubkeyG2.Y[1],
                    claimerMessageHash.X,
                    claimerMessageHash.Y
                )
            )
        ) % BN254.FR_MODULUS;

        // e(sigma + P * gamma, [-1]_2) = e(H(m) + [1]_1 * gamma, P')
        require(
            BN254.pairing(
                params.pubkeyRegistrationSignature.plus(params.pubkeyG1.scalar_mul(gamma)),
                BN254.negGeneratorG2(),
                claimerMessageHash.plus(BN254.generatorG1().scalar_mul(gamma)),
                params.pubkeyG2
            ),
            BadBLSSignature()
        );

        validatorClaimer[pubkeyHash] = claimer;

        emit ClaimerSet(pubkeyHash, claimer);
    }

    /**
     * @dev Get the claimer address for a validator
     * @param blsPubkeyHash The hash of the BLS public key
     * @return The claimer address
     */
    function getClaimer(bytes32 blsPubkeyHash) external view returns (address) {
        return validatorClaimer[blsPubkeyHash];
    }

    /**
     * @dev Get the Merkle root
     * @return The Merkle root
     */
    function getMerkleRoot() public view returns (bytes32) {
        // The pending root is active if the activation timestamp is in the past
        if (block.timestamp > pendingMerkleRootActivationTimestamp) {
            return pendingMerkleRoot;
        }
        return merkleRoot;
    }

    /**
     * @dev Returns the domain separator used in the encoding of the signature for EIP712
     * @return The domain separator
     */
    function getDomainSeparator() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Returns the chain ID used in the domain separator
     * @return The chain ID
     */
    function getChainId() public view returns (uint256) {
        return block.chainid;
    }

    /**
     * @notice Returns the message hash that an validator must sign to register their BLS public key.
     * @param blsPubkeyHash The hash of the BLS public key
     * @param claimer The address that will be able to claim rewards
     */
    function getClaimerMessageHash(bytes32 blsPubkeyHash, address claimer) public view returns (BN254.G1Point memory) {
        return BN254.hashToG1(_hashTypedDataV4(keccak256(abi.encode(CLAIM_TYPEHASH, blsPubkeyHash, claimer))));
    }

    /**
     * @notice Get the hash of a BLS public key
     * @param pubkeyG1 The G1 public key
     * @return The hash of the BLS public key
     */
    function getBlsPubkeyHash(BN254.G1Point memory pubkeyG1) public pure returns (bytes32) {
        return BN254.hashG1Point(pubkeyG1);
    }
}
