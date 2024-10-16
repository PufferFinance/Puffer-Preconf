// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { MerkleUtils } from "./MerkleUtils.sol";

library BeaconChainHelperLib {
    address internal constant _BEACON_ROOT_CONTRACT = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    struct InclusionProof {
        // `Chunks` of the SSZ encoded validator
        bytes32[8] validator;
        // Index of the validator in the beacon state validator list
        uint256 validatorIndex;
        // Proof of inclusion of validator in beacon state validator list
        bytes32[] validatorProof;
        // Root of the validator list in the beacon state
        bytes32 validatorsRoot;
        // Proof of inclusion of validator list in the beacon state
        bytes32[] beaconStateProof;
        // Root of the beacon state
        bytes32 beaconStateRoot;
        // Proof of inclusion of beacon state in the beacon block
        bytes32[] beaconBlockProofForState;
        // Proof of inclusion of the validator index in the beacon block
        bytes32[] beaconBlockProofForProposerIndex;
        // Timestamp of the beacon block
        uint256 timestamp;
    }

    /// @dev The validator pub key failed verification against the pub key hash tree root in the validator chunks
    error InvalidValidatorBLSPubKey();
    /// @dev The proof that the validator is a part of the validator list is invalid.
    error ValidatorProofFailed();
    /// @dev The proof that the validator list is a part of the beacon state is invalid.
    error BeaconStateProofFailed();
    /// @dev The proof that the beacon state is a part of the beacon block is invalid.
    error BeaconBlockProofForStateFailed();
    /// @dev The proof that the actual validator index is a part of the beacon is invalid.
    error BeaconBlockProofForProposerIndex();

    function verifyValidator(InclusionProof memory inclusionProof) internal returns (bool) {
        (, bytes32 beaconBlockRoot) = getRootFromTimestamp(inclusionProof.timestamp);

        // Validator is verified against the validator list in the beacon state
        bytes32 validatorHashTreeRoot = MerkleUtils.merkleize(inclusionProof.validator);
        if (
            !MerkleUtils.verifyProof(
                inclusionProof.validatorProof,
                inclusionProof.validatorsRoot,
                validatorHashTreeRoot,
                inclusionProof.validatorIndex
            )
        ) {
            // Revert if the proof that the expected validator is a part of the validator
            // list in beacon state fails
            return false;
        }

        if (
            !MerkleUtils.verifyProof(
                inclusionProof.beaconStateProof, inclusionProof.beaconStateRoot, inclusionProof.validatorsRoot, 11
            )
        ) {
            // Revert if the proof that the validator list is a part of the beacon state fails
            return false;
        }

        // Beacon state is verified against the beacon block
        if (
            !MerkleUtils.verifyProof(
                inclusionProof.beaconBlockProofForState, beaconBlockRoot, inclusionProof.beaconStateRoot, 3
            )
        ) {
            // Revert if the proof for the beacon state being a part of the beacon block fails
            return false;
        }

        // Validator index is verified against the beacon block
        if (
            !MerkleUtils.verifyProof(
                inclusionProof.beaconBlockProofForProposerIndex,
                beaconBlockRoot,
                MerkleUtils.toLittleEndian(inclusionProof.validatorIndex),
                1
            )
        ) {
            // Revert if the proof that the proposer index is a part of the beacon block fails
            return false;
        }

        return true;
    }

    function verifyProposerAt(uint256 timestamp, uint256 proposerIndex, bytes32[2] memory proof)
        internal
        returns (bool)
    {
        // Returns the parent_root, so check the next slot of the target block
        (bool success, bytes32 beaconRootFromChain) = getRootFromTimestamp(timestamp + 12);
        assert(success);

        uint256 slot = timeStampToSlot(timestamp);

        bytes32 slotAndProposerIndexNode = sha256(
            abi.encodePacked(
                abi.encodePacked(MerkleUtils.to_little_endian_64(uint64(slot)), bytes24(0)),
                abi.encodePacked(MerkleUtils.to_little_endian_64(uint64(proposerIndex)), bytes24(0))
            )
        );

        bytes32 leftNode = sha256(abi.encodePacked(slotAndProposerIndexNode, proof[0]));
        bytes32 root = sha256(abi.encodePacked(leftNode, proof[1]));

        // Verify computed and expected beacon block roots match
        return root == beaconRootFromChain;
    }

    function getRootFromTimestamp(uint256 timestamp) internal returns (bool, bytes32) {
        (bool ret, bytes memory data) = _BEACON_ROOT_CONTRACT.call(bytes.concat(bytes32(timestamp)));
        return (ret, bytes32(data));
    }

    function timeStampToSlot(uint256 timestamp) internal view returns (uint256) {
        uint256 genesisBlockTimestamp;

        // TODO modify for mainnet
        if (block.chainid == 17000) {
            // Holesky
            genesisBlockTimestamp = 1695902400;
        } else if (block.chainid == 1) {
            // Mainnet
            genesisBlockTimestamp = 1606824023;
        } else if (block.chainid == 7014190335) {
            // Helder
            genesisBlockTimestamp = 1718967660;
        }

        return ((timestamp - genesisBlockTimestamp) / 12);
    }
}
