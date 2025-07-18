// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IUnifiRewardsDistributor } from "./interfaces/IUnifiRewardsDistributor.sol";
import { BLS } from "./library/BLS.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title Unifi Rewards Distributor
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract UnifiRewardsDistributor is IUnifiRewardsDistributor, AccessManaged, EIP712, ReentrancyGuard {
    using Address for address payable;
    using SafeERC20 for IERC20;

    /// @dev The typehash for the RegisterClaimer function
    bytes32 public constant REWARDS_DISTRIBUTION_TYPEHASH = keccak256("RegisterClaimer(address claimer,uint256 nonce)");

    /// @dev The delay for the Merkle root to be set
    uint256 public constant MERKLE_ROOT_DELAY = 7 days;

    /// @dev Constant address to represent native ETH token
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @dev the mapping of BLS pubkey hash to claimer address
    mapping(bytes32 blsPubkeyHash => address claimer) public validatorClaimer;

    /// @dev the mapping of token address to BLS pubkey hash to claimed amount
    mapping(address token => mapping(bytes32 blsPubkeyHash => uint256 claimedAmount)) public validatorClaimedAmount;

    /// @dev The Merkle root of the latest cumulative distribution
    bytes32 public merkleRoot;
    /// @dev The pending Merkle root. This merkle root will become active after the delay
    bytes32 public pendingMerkleRoot;
    /// @dev The timestamp when the pending Merkle root will become active
    uint256 public pendingMerkleRootActivationTimestamp;
    /// @dev The mapping of BLS pubkey hash to nonce
    mapping(bytes32 pubkeyHash => uint256 nonce) public nonces;

    constructor(address accessManager) AccessManaged(accessManager) EIP712("UnifiRewardsDistributor", "1") { }

    /**
     * @notice Claim the unclaimed rewards for multiple validators
     * They all must have the same claimer set.
     * @param token The token address to claim (use NATIVE_TOKEN for ETH)
     * @param blsPubkeyHashes The hashes of the BLS public keys
     * @param amounts The total cumulative earned amounts
     * @param proofs The proofs of the claims
     */
    function claimRewards(
        address token,
        bytes32[] calldata blsPubkeyHashes,
        uint256[] calldata amounts,
        bytes32[][] calldata proofs
    ) external nonReentrant {
        if (blsPubkeyHashes.length != amounts.length || amounts.length != proofs.length) revert InvalidInput();
        if (token == address(0)) revert InvalidInput();

        // Get the claimer for the first pubkey hash
        address claimer = validatorClaimer[blsPubkeyHashes[0]];
        if (claimer == address(0)) revert ClaimerNotSet();

        uint256 totalAmountToClaim = _processClaims({
            token: token,
            blsPubkeyHashes: blsPubkeyHashes,
            amounts: amounts,
            proofs: proofs,
            claimer: claimer
        });

        // Send the total amount to the claimer
        if (token == NATIVE_TOKEN) {
            payable(claimer).sendValue(totalAmountToClaim);
        } else {
            IERC20(token).safeTransfer(claimer, totalAmountToClaim);
        }
    }

    /**
     * @dev Processes claims for multiple validators and returns the total claim amount
     * @param token The token address to claim
     * @param blsPubkeyHashes The hashes of the BLS public keys
     * @param amounts The total cumulative earned amounts
     * @param proofs The proofs of the claims
     * @param claimer The claimer address that must be set for all validators
     * @return totalAmountToClaim The total amount to claim
     */
    function _processClaims(
        address token,
        bytes32[] calldata blsPubkeyHashes,
        uint256[] calldata amounts,
        bytes32[][] calldata proofs,
        address claimer
    ) private returns (uint256 totalAmountToClaim) {
        totalAmountToClaim = 0;

        for (uint256 i = 0; i < blsPubkeyHashes.length; ++i) {
            // All proofs must have the same claimer
            if (claimer != validatorClaimer[blsPubkeyHashes[i]]) revert InvalidInput();

            uint256 claimedSoFar = validatorClaimedAmount[token][blsPubkeyHashes[i]];
            uint256 amountToClaim = amounts[i] > claimedSoFar ? amounts[i] - claimedSoFar : 0;
            if (amountToClaim == 0) revert NothingToClaim();

            // Update the claimed amount to the latest amount
            validatorClaimedAmount[token][blsPubkeyHashes[i]] = amounts[i];

            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(blsPubkeyHashes[i], token, amounts[i]))));
            if (!MerkleProof.verifyCalldata(proofs[i], getMerkleRoot(), leaf)) revert InvalidProof();

            emit RewardsClaimed(blsPubkeyHashes[i], token, amountToClaim);

            totalAmountToClaim += amountToClaim;
        }

        return totalAmountToClaim;
    }

    /**
     * @notice Set the Merkle root of the latest cumulative distribution
     * @dev This function will be callable by the backend service
     * @param newMerkleRoot The new Merkle root
     */
    function setNewMerkleRoot(bytes32 newMerkleRoot) external restricted {
        if (newMerkleRoot == bytes32(0)) revert MerkleRootCannotBeZero();
        if (pendingMerkleRoot != bytes32(0) && block.timestamp >= pendingMerkleRootActivationTimestamp) {
            merkleRoot = pendingMerkleRoot;
        }
        pendingMerkleRoot = newMerkleRoot;
        uint256 activationTimestamp = block.timestamp + MERKLE_ROOT_DELAY;
        pendingMerkleRootActivationTimestamp = activationTimestamp;
        emit MerkleRootSet(newMerkleRoot, activationTimestamp);
    }

    /**
     * @notice Cancel the pending Merkle root
     * @dev Multiple accounts `watchers` will be double checking the newly posted Merkle root, 
     * and cancel the pending if it is incorrect
     */
    function cancelPendingMerkleRoot() external restricted {
        if (block.timestamp < pendingMerkleRootActivationTimestamp) {
            bytes32 merkleRootToCancel = pendingMerkleRoot;
            pendingMerkleRoot = bytes32(0);
            pendingMerkleRootActivationTimestamp = 0;
            emit PendingMerkleRootCancelled(merkleRootToCancel);
        } else {
            revert NoPendingMerkleRoot();
        }
    }

    /**
     * @notice Registers the `claimer`'s address for the validator's BLS public keys
     * @param claimer The address of the claimer to register.
     * @param params is an array of structs containing the G1 & G2 public keys of the validator, and a signature
     * proving their ownership
     */
    function registerClaimer(address claimer, PubkeyRegistrationParams[] calldata params) external {
        for (uint256 i = 0; i < params.length; ++i) {
            bytes32 pubKeyHash = getBlsPubkeyHash(params[i].publicKey);

            bytes32 structHash = keccak256(abi.encode(REWARDS_DISTRIBUTION_TYPEHASH, claimer, _useNonce(pubKeyHash)));

            BLS.G2Point memory messagePoint = BLS.hashToG2(abi.encodePacked(_hashTypedDataV4(structHash)));

            BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
            g1Points[0] = NEGATED_G1_GENERATOR();
            g1Points[1] = params[i].publicKey;

            BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
            g2Points[0] = params[i].signature;
            g2Points[1] = messagePoint;

            bool valid = BLS.pairing(g1Points, g2Points);
            // This will revert if the signature is invalid / replayed
            if (!valid) revert BadBLSSignature();

            validatorClaimer[pubKeyHash] = claimer;

            emit ClaimerSet(pubKeyHash, claimer);
        }
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
        // The pending root is active if the activation timestamp is in the past and pendingMerkleRoot is not zero
        if (block.timestamp >= pendingMerkleRootActivationTimestamp && pendingMerkleRoot != bytes32(0)) {
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
     * @notice A helper function to get the message hash that a validator must sigh with their validator's BLS
     * public key
     * @param claimer The claimer address
     * @param pubkeyHash The hash of the BLS public key
     * @return The message hash
     */
    function getMessageHash(address claimer, bytes32 pubkeyHash) external view returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encode(REWARDS_DISTRIBUTION_TYPEHASH, claimer, nonces[pubkeyHash]));
        return abi.encodePacked(_hashTypedDataV4(messageHash));
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

    function _useNonce(bytes32 pubkeyHash) internal virtual returns (uint256) {
        // For each account, the nonce has an initial value of 0, can only be incremented by one, and cannot be
        // decremented or reset. This guarantees that the nonce never overflows.
        unchecked {
            // It is important to do x++ and not ++x here.
            return nonces[pubkeyHash]++;
        }
    }

    /**
     * @notice Fallback function to make the contract payable
     * @dev This allows the contract to receive ETH
     */
    receive() external payable { }

    /**
     * @notice Allows the admin to rescue any funds from the contract
     * @param token The token address to rescue (use NATIVE_TOKEN for ETH)
     * @param recipient The address to send the rescued funds to
     * @param amount The amount to rescue
     * @dev Only callable by the admin
     */
    function rescueFunds(address token, address recipient, uint256 amount) external restricted {
        if (recipient == address(0)) revert InvalidInput();
        if (amount == 0) revert InvalidInput();

        if (token == NATIVE_TOKEN) {
            payable(recipient).sendValue(amount);
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit RescuedFunds(token, recipient, amount);
    }
}
