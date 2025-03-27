// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UnifiRewardsDistributor } from "../../src/UnifiRewardsDistributor.sol";
import { IUnifiRewardsDistributor } from "../../src/interfaces/IUnifiRewardsDistributor.sol";
import { BLS } from "../../src/library/BLS.sol";
import { UnitTestHelper } from "../helpers/UnitTestHelper.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Merkle } from "murky/Merkle.sol";

contract UnifiRewardsDistributorTest is UnitTestHelper {
    struct MerkleProofData {
        bytes32 blsPubkeyHash;
        uint256 amount;
    }

    using Strings for uint256;

    UnifiRewardsDistributor internal distributor;
    Merkle internal rewardsMerkleProof;
    bytes32[] internal rewardsMerkleProofData;

    // Dummy BLS private key (never use in production!)
    uint256 aliceValidatorPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    bytes32 aliceValidatorPubkeyHash = hex"349f9310273a8c4383749e137887aa02e8f1fada8f181449796da01aec23455a";
    address alice = makeAddr("alice");

    uint256 bobValidatorPrivateKey = 7;
    bytes32 bobValidatorPubkeyHash = hex"e711030c34f9fc82f04c360494b9c94f17a43fe72a5860f057f098f48d382380";
    address bob = makeAddr("bob");

    // Generated using staking-deposit-cli
    uint256 charlieValidatorPrivateKey = 23024678602024712540067510915809205418841443088598876011398808352199993287749;
    bytes charlieValidatorPubkey =
        hex"83e6a728d627638a33a73003ff9a072f0297dbca72ae0c2b9e4dfb1025ce96fcfc4c5322a6d3c35f4373d3974279f84c";
    bytes32 charlieValidatorPubkeyHash = hex"aab3ff930108a1dba48d8b2dd82024e1772e6fad0f3d73eeac69420520c19de7";
    // pubkey hash is sha256(abi.encodePacked(hex"85ad844d945152c879efb271abc77be88ca4edd97df69200dc0abfbb6cf0a769311022c7aad809b579944fdb405a62b2", bytes16(0)))
    address charlie = makeAddr("charlie");

    function setUp() public override {
        distributor = new UnifiRewardsDistributor(address(this));
    }

    function test_register_claimer_zero_key() public {
        // Registers a claimer for zero key
        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.ClaimerSet(
            hex"012893657d8eb2efad4de0a91bcd0e39ad9837745dec3ea923737ea803fc8e3d", alice
        );
        distributor.registerClaimer(
            alice,
            IUnifiRewardsDistributor.PubkeyRegistrationParams({
                signature: BLS.G2Point({
                    x_c0_a: bytes32(0),
                    x_c0_b: bytes32(0),
                    x_c1_a: bytes32(0),
                    x_c1_b: bytes32(0),
                    y_c0_a: bytes32(0),
                    y_c0_b: bytes32(0),
                    y_c1_a: bytes32(0),
                    y_c1_b: bytes32(0)
                }),
                publicKey: BLS.G1Point({ x_a: bytes32(0), x_b: bytes32(0), y_a: bytes32(0), y_b: bytes32(0) })
            })
        );
    }

    function test_register_claimer_charlie_validator() public {
        BLS.G1Point memory publicKey = BLS.G1Point({
            x_a: bytes32(0x0000000000000000000000000000000003e6a728d627638a33a73003ff9a072f),
            x_b: bytes32(0x0297dbca72ae0c2b9e4dfb1025ce96fcfc4c5322a6d3c35f4373d3974279f84c),
            y_a: bytes32(0x000000000000000000000000000000000015ce87d1de408f3de766c379aa0331),
            y_b: bytes32(0x449465dba3f66c63eb8c4cbb96ed95e8da093c7b439b01a2e7d13ecf538e50ac)
        });

        distributor.registerClaimer(
            charlie,
            IUnifiRewardsDistributor.PubkeyRegistrationParams({
                signature: BLS.G2Point({
                    x_c0_a: bytes32(0x00000000000000000000000000000000194a8be661cee6a16c2d4989b68f4fd3),
                    x_c0_b: bytes32(0x49dfbcb508a3e1dbb0ddd58e7cb464e984160f4d8a5acc8ae75e7f41b56068d1),
                    x_c1_a: bytes32(0x0000000000000000000000000000000001d5ce2d523c1add9ffbf24efe1f6fb5),
                    x_c1_b: bytes32(0x98ed5344001b520b06c78cf4c842539dacce3319e68119399d3d330d6d05f4b1),
                    y_c0_a: bytes32(0x000000000000000000000000000000000e6090924e13feaa93b4c149418e7b28),
                    y_c0_b: bytes32(0x716c191398cb6dd34f04007c38d72e5e327028a7e553d14632da6a5c72a3c63c),
                    y_c1_a: bytes32(0x0000000000000000000000000000000005f41de8e5a8045a614c64adb240ecf7),
                    y_c1_b: bytes32(0xd0f95c906880bfd1eb8bc05387f43e4979bd1ee1496f9313bf5c7ff92cd9d386)
                }),
                publicKey: publicKey
            })
        );
    }

    function _buildMerkleProof(MerkleProofData[] memory merkleProofDatas) internal returns (bytes32 root) {
        rewardsMerkleProof = new Merkle();

        rewardsMerkleProofData = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory merkleProofData = merkleProofDatas[i];
            rewardsMerkleProofData[i] =
                keccak256(bytes.concat(keccak256(abi.encode(merkleProofData.blsPubkeyHash, merkleProofData.amount))));
        }

        root = rewardsMerkleProof.getRoot(rewardsMerkleProofData);
    }

    function test_setup() public view {
        assertEq(distributor.getChainId(), block.chainid, "Chain ID should be correct");
    }

    function test_setMerkleRoot() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: bytes32("alice"), amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.MerkleRootSet(merkleRoot, block.timestamp + 3 days);
        distributor.setNewMerkleRoot(merkleRoot);
    }

    function test_setMerkleRoot_zeroRoot() public {
        vm.expectRevert(IUnifiRewardsDistributor.MerkleRootCannotBeZero.selector);
        distributor.setNewMerkleRoot(bytes32(0));
    }

    function testRevert_register_claimer_same_nonce() public {
        // Generate public keys
        BLS.G1Point memory publicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));

        bytes32 pubkeyHash = distributor.getBlsPubkeyHash(publicKey);

        bytes memory message = distributor.getMessageHash(alice, pubkeyHash);

        BLS.G2Point memory messagePoint = BLS.hashToG2(message);

        assertEq(block.chainid, 31337, "Chain ID should be 31337");
        // Create signature (H(m) * privateKey)
        BLS.G2Point memory signature = _blsg2mul(messagePoint, bytes32(aliceValidatorPrivateKey));

        // Build params
        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: signature, publicKey: publicKey });

        // Execute registration
        vm.prank(alice);
        distributor.registerClaimer(alice, params);

        // Verify registration
        assertEq(distributor.getClaimer(pubkeyHash), alice);

        // Try to register again with the same signature (signature replay)
        // Should revert with BadBLSSignature
        vm.prank(alice);
        vm.expectRevert(IUnifiRewardsDistributor.BadBLSSignature.selector);
        distributor.registerClaimer(alice, params);
    }

    function test_ClaimRewards() public {
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32[] memory pubkeyHashes = new bytes32[](2);
        pubkeyHashes[0] = distributor.getBlsPubkeyHash(alicePublicKey);
        pubkeyHashes[1] = distributor.getBlsPubkeyHash(bobPublicKey);

        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[0], amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[1], amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time so that the pending root becomes active
        vm.warp(block.timestamp + 4 days);

        // Set claimer for Alice
        test_registerClaimer();

        _registerClaimer(bobValidatorPrivateKey, bob, alice);

        // Deal some ETH to the distributor, so that it has some balance
        vm.deal(address(distributor), 10 ether);

        // Alice claims the rewards
        vm.prank(alice);

        assertEq(alice.balance, 0, "Alice should have 0 balance");

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1 ether;
        amounts[1] = 2 ether;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);
        proofs[1] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        distributor.claimRewards(pubkeyHashes, amounts, proofs);

        assertEq(alice.balance, 3 ether, "Alice should have received 3 ether");
        assertEq(bob.balance, 0 ether, "Bob should have received 0 ether");

        vm.expectRevert(IUnifiRewardsDistributor.NothingToClaim.selector);
        distributor.claimRewards(pubkeyHashes, amounts, proofs);
    }

    function test_revertClaimerNotSet() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: aliceValidatorPubkeyHash, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        // Empty proof, doesn't matter
        bytes32[][] memory aliceProofs = new bytes32[][](1);

        bytes32[] memory alicePubkeyHashes = new bytes32[](1);
        alicePubkeyHashes[0] = aliceValidatorPubkeyHash;

        uint256[] memory aliceAmounts = new uint256[](1);
        aliceAmounts[0] = 1 ether;

        vm.expectRevert(IUnifiRewardsDistributor.ClaimerNotSet.selector);
        distributor.claimRewards(alicePubkeyHashes, aliceAmounts, aliceProofs);
    }

    function test_revertInvalidProof() public {
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        bytes32 alicePubkeyHash = distributor.getBlsPubkeyHash(alicePublicKey);

        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: alicePubkeyHash, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        vm.warp(block.timestamp + 4 days);

        // Set claimer for Alice
        test_registerClaimer();

        // Empty proof, doesn't matter
        bytes32[][] memory aliceProofs = new bytes32[][](1);
        bytes32[] memory alicePubkeyHashes = new bytes32[](1);
        alicePubkeyHashes[0] = alicePubkeyHash;

        uint256[] memory aliceAmounts = new uint256[](1);
        aliceAmounts[0] = 1 ether;

        vm.expectRevert(IUnifiRewardsDistributor.InvalidProof.selector);
        distributor.claimRewards(alicePubkeyHashes, aliceAmounts, aliceProofs);
    }

    function test_cancelPendingMerkleRoot() public {
        bytes32 newMerkleRoot = keccak256("new merkle root");

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.MerkleRootSet(newMerkleRoot, block.timestamp + 3 days);
        distributor.setNewMerkleRoot(newMerkleRoot);

        assertEq(distributor.getMerkleRoot(), bytes32(0), "Merkle root should be 0");

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.PendingMerkleRootCancelled(newMerkleRoot);
        distributor.cancelPendingMerkleRoot();
    }

    function test_registerClaimer() public {
        // Generate public keys
        BLS.G1Point memory publicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));

        bytes32 pubkeyHash = distributor.getBlsPubkeyHash(publicKey);

        bytes memory message = distributor.getMessageHash(alice, pubkeyHash);

        BLS.G2Point memory messagePoint = BLS.hashToG2(message);

        assertEq(block.chainid, 31337, "Chain ID should be 31337");
        // Create signature (H(m) * privateKey)
        BLS.G2Point memory signature = _blsg2mul(messagePoint, bytes32(aliceValidatorPrivateKey));

        // Build params
        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: signature, publicKey: publicKey });

        // Execute registration
        vm.prank(alice);
        distributor.registerClaimer(alice, params);

        // Verify registration
        assertEq(distributor.getClaimer(pubkeyHash), alice);
    }

    function _registerClaimer(uint256 blsPrivateKey, address caller, address claimer) internal {
        // Generate public keys
        BLS.G1Point memory publicKey = _blsg1mul(G1_GENERATOR(), bytes32(blsPrivateKey));

        bytes32 pubkeyHash = distributor.getBlsPubkeyHash(publicKey);

        bytes memory message = distributor.getMessageHash(claimer, pubkeyHash);

        BLS.G2Point memory messagePoint = BLS.hashToG2(message);

        // Create signature (H(m) * privateKey)
        BLS.G2Point memory signature = _blsg2mul(messagePoint, bytes32(blsPrivateKey));

        // Build params
        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: signature, publicKey: publicKey });

        // Execute registration
        vm.prank(caller);
        distributor.registerClaimer(claimer, params);

        // Verify registration
        assertEq(distributor.getClaimer(pubkeyHash), claimer);
    }

    function test_revertRegisterClaimer_badSignature() public {
        BLS.G1Point memory publicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G2Point memory signature;

        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: signature, publicKey: publicKey });

        vm.expectRevert(IUnifiRewardsDistributor.BadBLSSignature.selector);
        distributor.registerClaimer(alice, params);
    }

    function G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point({
            x_a: bytes32(uint256(31827880280837800241567138048534752271)),
            x_b: bytes32(uint256(88385725958748408079899006800036250932223001591707578097800747617502997169851)),
            y_a: bytes32(uint256(11568204302792691131076548377920244452)),
            y_b: bytes32(uint256(114417265404584670498511149331300188430316142484413708742216858159411894806497))
        });
    }

    function NEGATED_G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point({
            x_a: bytes32(uint256(31827880280837800241567138048534752271)),
            x_b: bytes32(uint256(88385725958748408079899006800036250932223001591707578097800747617502997169851)),
            y_a: bytes32(uint256(22997279242622214937712647648895181298)),
            y_b: bytes32(uint256(46816884707101390882112958134453447585552332943769894357249934112654335001290))
        });
    }

    function _blsg1mul(BLS.G1Point memory g1, bytes32 privateKey) private view returns (BLS.G1Point memory) {
        BLS.G1Point[] memory points = new BLS.G1Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        points[0] = g1;
        scalars[0] = privateKey;

        return BLS.msm(points, scalars);
    }

    function _blsg2mul(BLS.G2Point memory g2, bytes32 scalar) private view returns (BLS.G2Point memory) {
        BLS.G2Point[] memory points = new BLS.G2Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        points[0] = g2;
        scalars[0] = scalar;

        return BLS.msm(points, scalars);
    }
}
