// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IUnifiRewardsDistributor } from "./interfaces/IUnifiRewardsDistributor.sol";

import { BLS } from "./library/BLS.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract UnifiRewardsDistributor is IUnifiRewardsDistributor, Ownable2Step {
    using Address for address payable;

    /// @dev The delay for the Merkle root to be set
    uint256 public constant MERKLE_ROOT_DELAY = 1 days;

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

    constructor() Ownable(msg.sender) { }

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
        // The message that the Validator must sign with their BLS private key
        // chainId is the L2 rollup chainId on which the Claimer will claim the rewards
        // The message is the chainId + address of the claimer
        bytes32 message = keccak256(abi.encode(block.chainid, claimer));

        BLS.G2Point memory messagePoint = BLS.toG2(BLS.Fp2(0, 0, 0, message));

        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = NEGATED_G1_GENERATOR();
        g1Points[1] = params.publicKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = params.signature;
        g2Points[1] = messagePoint;

        bool valid = BLS.pairing(g1Points, g2Points);
        require(valid, BadBLSSignature());

        bytes32 pubKeyHash = getBlsPubkeyHash(params.publicKey);

        validatorClaimer[pubKeyHash] = claimer;

        emit ClaimerSet(pubKeyHash, claimer);
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
     * @dev Returns the chain ID used in the domain separator
     * @return The chain ID
     */
    function getChainId() public view returns (uint256) {
        return block.chainid;
    }

    /**
     * @notice Get the hash of a BLS public key
     * @param pubkeyG1 The G1 public key
     * @return The hash of the BLS public key
     */
    function getBlsPubkeyHash(BLS.G1Point memory pubkeyG1) public pure returns (bytes32) {
        return keccak256(abi.encode(pubkeyG1.x_a, pubkeyG1.x_b, pubkeyG1.y_a, pubkeyG1.y_b));
    }

    /**
     * @notice Returns the negated G1 generator
     * @return The negated G1 generator
     */
    function NEGATED_G1_GENERATOR() public pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(uint256(31827880280837800241567138048534752271)),
            bytes32(uint256(88385725958748408079899006800036250932223001591707578097800747617502997169851)),
            bytes32(uint256(22997279242622214937712647648895181298)),
            bytes32(uint256(46816884707101390882112958134453447585552332943769894357249934112654335001290))
        );
    }
}
