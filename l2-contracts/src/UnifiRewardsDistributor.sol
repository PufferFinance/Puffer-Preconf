// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IUnifiRewardsDistributor } from "./interfaces/IUnifiRewardsDistributor.sol";
import { BN254 } from "./library/BN254.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract UnifiRewardsDistributor is IUnifiRewardsDistributor, EIP712, Ownable2Step {
    using BN254 for BN254.G1Point;

    error CannotRegisterZeroPubKey();
    error BadBLSSignature();

    event ClaimerSet(bytes32 indexed blsPubkeyHash, address indexed claimer);

    /// @dev the hash of the zero pubkey aka BN254.G1Point(0,0)
    bytes32 internal constant _ZERO_PK_HASH = hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";

    mapping(bytes32 blsPubkeyHash => address claimer) public validatorToClaimer;
    mapping(bytes32 blsPubkeyHash => uint256 claimedAmount) public validatorToClaimedAmount;

    // EIP-712 type definitions
    bytes32 public constant CLAIM_TYPEHASH = keccak256("SetClaimer(bytes32 blsPubkeyHash,address claimer)");
    string public constant DOMAIN_NAME = "UnifiRewardsDistributor";
    string public constant DOMAIN_VERSION = "1";

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

        validatorToClaimer[pubkeyHash] = claimer;

        emit ClaimerSet(pubkeyHash, claimer);
    }

    /**
     * @dev Get the claimer address for a validator
     * @param blsPubkeyHash The hash of the BLS public key
     * @return The claimer address
     */
    function getClaimer(bytes32 blsPubkeyHash) external view returns (address) {
        return validatorToClaimer[blsPubkeyHash];
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
