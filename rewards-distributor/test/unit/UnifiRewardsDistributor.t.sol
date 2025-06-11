// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UnifiRewardsDistributor } from "../../src/UnifiRewardsDistributor.sol";
import { IUnifiRewardsDistributor } from "../../src/interfaces/IUnifiRewardsDistributor.sol";
import { BLS } from "../../src/library/BLS.sol";
import { UnitTestHelper } from "../helpers/UnitTestHelper.sol";
import { Roles } from "../../script/library/Roles.sol";

import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Merkle } from "murky/Merkle.sol";

// Simple mock token for testing
contract MockToken is ERC20 {
    constructor() ERC20("MockToken", "MTK") {
        _mint(msg.sender, 1000 ether);
    }
}

// Reentrancy attacker for testing
contract ReentrancyAttacker {
    UnifiRewardsDistributor public distributor;
    bytes32[] public blsPubkeyHashes;
    uint256[] public amounts;
    bytes32[][] public proofs;
    address public token;
    bool public attackMode;
    uint256 public attackCount;
    bool public tokenClaimSucceeded;

    // For cross-token attack
    bytes32[] public tokenBlsPubkeyHashes;
    uint256[] public tokenAmounts;
    bytes32[][] public tokenProofs;
    address public tokenAddress;
    bool public crossTokenAttack;

    constructor(UnifiRewardsDistributor _distributor) {
        distributor = _distributor;
    }

    function setAttackParams(
        address _token,
        bytes32[] memory _blsPubkeyHashes,
        uint256[] memory _amounts,
        bytes32[][] memory _proofs
    ) external {
        token = _token;
        blsPubkeyHashes = new bytes32[](_blsPubkeyHashes.length);
        amounts = new uint256[](_amounts.length);
        proofs = new bytes32[][](_proofs.length);

        for (uint256 i = 0; i < _blsPubkeyHashes.length; i++) {
            blsPubkeyHashes[i] = _blsPubkeyHashes[i];
            amounts[i] = _amounts[i];
            proofs[i] = _proofs[i];
        }
    }

    function setCrossTokenAttackParams(
        address _token,
        bytes32[] memory _blsPubkeyHashes,
        uint256[] memory _amounts,
        bytes32[][] memory _proofs
    ) external {
        tokenAddress = _token;
        tokenBlsPubkeyHashes = new bytes32[](_blsPubkeyHashes.length);
        tokenAmounts = new uint256[](_amounts.length);
        tokenProofs = new bytes32[][](_proofs.length);

        for (uint256 i = 0; i < _blsPubkeyHashes.length; i++) {
            tokenBlsPubkeyHashes[i] = _blsPubkeyHashes[i];
            tokenAmounts[i] = _amounts[i];
            tokenProofs[i] = _proofs[i];
        }

        crossTokenAttack = true;
    }

    function attack() external {
        attackMode = true;
        attackCount = 0;
        tokenClaimSucceeded = false;
        distributor.claimRewards(token, blsPubkeyHashes, amounts, proofs);
    }

    // This will be called when ETH is received
    receive() external payable {
        if (attackMode && attackCount < 1) {
            attackCount++;

            if (crossTokenAttack) {
                // Try to claim tokens during ETH reentrancy
                try distributor.claimRewards(tokenAddress, tokenBlsPubkeyHashes, tokenAmounts, tokenProofs) {
                    // Attack succeeded
                    tokenClaimSucceeded = true;
                } catch {
                    // Attack failed, which is expected
                    tokenClaimSucceeded = false;
                }
            } else {
                // Try to reenter and claim ETH again
                try distributor.claimRewards(token, blsPubkeyHashes, amounts, proofs) {
                    // Attack succeeded
                } catch {
                    // Attack failed, which is expected
                }
            }
        }
    }
}

contract UnifiRewardsDistributorTest is UnitTestHelper {
    struct MerkleProofData {
        bytes32 blsPubkeyHash;
        address token;
        uint256 amount;
    }

    using Strings for uint256;

    UnifiRewardsDistributor internal distributor;
    Merkle internal rewardsMerkleProof;
    bytes32[] internal rewardsMerkleProofData;
    MockToken internal mockToken;
    ReentrancyAttacker internal attacker;

    // Dummy BLS private key (never use in production!)
    uint256 aliceValidatorPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    bytes alicePubKey =
        hex"972a59075fca0729b40b2cea5bb9685afdd219e77407e13631664c53b847cdcad45ab174a073aaa4122ad813fa094485";
    address alice = makeAddr("alice");

    uint256 bobValidatorPrivateKey = 7;
    bytes bobPubKey =
        hex"b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7";
    address bob = makeAddr("bob");

    // Generated using staking-deposit-cli
    uint256 charlieValidatorPrivateKey = 23024678602024712540067510915809205418841443088598876011398808352199993287749;
    bytes charlieValidatorPubkey =
        hex"83e6a728d627638a33a73003ff9a072f0297dbca72ae0c2b9e4dfb1025ce96fcfc4c5322a6d3c35f4373d3974279f84c";
    bytes32 charlieValidatorPubkeyHash = hex"aab3ff930108a1dba48d8b2dd82024e1772e6fad0f3d73eeac69420520c19de7";
    address charlie = makeAddr("charlie");

    // Store NATIVE_TOKEN reference once after deployment to use throughout the tests

    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    AccessManager internal manager;

    uint64 MERKLE_ROOT_POSTER_ROLE = Roles.MERKLE_ROOT_POSTER_ROLE;
    uint64 MERKLE_ROOT_CANCELLER_ROLE = Roles.MERKLE_ROOT_CANCELLER_ROLE;
    uint64 FUNDS_RESCUER_ROLE = Roles.FUNDS_RESCUER_ROLE;

    function setUp() public override {
        manager = new AccessManager(address(this));

        distributor = new UnifiRewardsDistributor(address(manager));
        mockToken = new MockToken();
        attacker = new ReentrancyAttacker(distributor);

        bytes4[] memory merkleRootPosterSelectors = new bytes4[](1);
        merkleRootPosterSelectors[0] = UnifiRewardsDistributor.setNewMerkleRoot.selector;

        bytes4[] memory merkleRootCancellerSelectors = new bytes4[](1);
        merkleRootCancellerSelectors[0] = UnifiRewardsDistributor.cancelPendingMerkleRoot.selector;

        manager.setTargetFunctionRole(address(distributor), merkleRootPosterSelectors, MERKLE_ROOT_POSTER_ROLE);
        manager.setTargetFunctionRole(address(distributor), merkleRootCancellerSelectors, MERKLE_ROOT_CANCELLER_ROLE);

        manager.grantRole(MERKLE_ROOT_POSTER_ROLE, address(this), 0);
        manager.grantRole(MERKLE_ROOT_CANCELLER_ROLE, address(this), 0);
    }

    function test_register_claimer_zero_key() public {
        IUnifiRewardsDistributor.PubkeyRegistrationParams[] memory params =
            new IUnifiRewardsDistributor.PubkeyRegistrationParams[](1);
        params[0] = IUnifiRewardsDistributor.PubkeyRegistrationParams({
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
        });

        // Registers a claimer for zero key
        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.ClaimerSet(
            hex"012893657d8eb2efad4de0a91bcd0e39ad9837745dec3ea923737ea803fc8e3d", alice
        );
        distributor.registerClaimer(alice, params);
    }

    function _buildMerkleProof(MerkleProofData[] memory merkleProofDatas) internal returns (bytes32 root) {
        rewardsMerkleProof = new Merkle();

        rewardsMerkleProofData = new bytes32[](merkleProofDatas.length);

        for (uint256 i = 0; i < merkleProofDatas.length; ++i) {
            MerkleProofData memory merkleProofData = merkleProofDatas[i];
            rewardsMerkleProofData[i] = keccak256(
                bytes.concat(
                    keccak256(abi.encode(merkleProofData.blsPubkeyHash, merkleProofData.token, merkleProofData.amount))
                )
            );
        }

        root = rewardsMerkleProof.getRoot(rewardsMerkleProofData);
    }

    function test_setup() public view {
        assertEq(distributor.getChainId(), block.chainid, "Chain ID should be correct");
    }

    function test_setMerkleRoot() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: bytes32("alice"), token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), token: NATIVE_TOKEN, amount: 2 ether });
        merkleProofDatas[2] =
            MerkleProofData({ blsPubkeyHash: bytes32("charlie"), token: NATIVE_TOKEN, amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.MerkleRootSet(merkleRoot, block.timestamp + 7 days);
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

        // Build params
        IUnifiRewardsDistributor.PubkeyRegistrationParams[] memory params =
            new IUnifiRewardsDistributor.PubkeyRegistrationParams[](1);
        params[0] = IUnifiRewardsDistributor.PubkeyRegistrationParams({
            signature: _blsg2mul(messagePoint, bytes32(aliceValidatorPrivateKey)),
            publicKey: publicKey
        });

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
        BLS.G1Point memory charliePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(charlieValidatorPrivateKey));

        bytes32[] memory pubkeyHashes = new bytes32[](2);
        pubkeyHashes[0] = distributor.getBlsPubkeyHash(alicePublicKey);
        pubkeyHashes[1] = distributor.getBlsPubkeyHash(bobPublicKey);

        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[0], token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[1], token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[2] = MerkleProofData({
            blsPubkeyHash: distributor.getBlsPubkeyHash(charliePublicKey),
            token: NATIVE_TOKEN,
            amount: 2 ether
        });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time so that the pending root becomes active
        vm.warp(block.timestamp + 8 days);

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
        amounts[1] = 1 ether;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);
        proofs[1] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        distributor.claimRewards(NATIVE_TOKEN, pubkeyHashes, amounts, proofs);

        assertEq(
            distributor.validatorClaimedAmount(NATIVE_TOKEN, pubkeyHashes[0]),
            1 ether,
            "claimed amount should be 1 ether"
        );
        assertEq(
            distributor.validatorClaimedAmount(NATIVE_TOKEN, pubkeyHashes[1]),
            1 ether,
            "claimed amount should be 1 ether"
        );

        assertEq(alice.balance, 2 ether, "Alice should have received 2 ether");
        assertEq(bob.balance, 0 ether, "Bob should have received 0 ether");

        vm.expectRevert(IUnifiRewardsDistributor.NothingToClaim.selector);
        distributor.claimRewards(NATIVE_TOKEN, pubkeyHashes, amounts, proofs);
    }

    function test_ClaimTokenRewards() public {
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));
        BLS.G1Point memory charliePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(charlieValidatorPrivateKey));

        bytes32[] memory pubkeyHashes = new bytes32[](2);
        pubkeyHashes[0] = distributor.getBlsPubkeyHash(alicePublicKey);
        pubkeyHashes[1] = distributor.getBlsPubkeyHash(bobPublicKey);

        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] =
            MerkleProofData({ blsPubkeyHash: pubkeyHashes[0], token: address(mockToken), amount: 1 ether });
        merkleProofDatas[1] =
            MerkleProofData({ blsPubkeyHash: pubkeyHashes[1], token: address(mockToken), amount: 1 ether });
        merkleProofDatas[2] = MerkleProofData({
            blsPubkeyHash: distributor.getBlsPubkeyHash(charliePublicKey),
            token: address(mockToken),
            amount: 2 ether
        });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time so that the pending root becomes active
        vm.warp(block.timestamp + 8 days);

        // Set claimer for Alice
        test_registerClaimer();

        _registerClaimer(bobValidatorPrivateKey, bob, alice);

        // Transfer tokens to the distributor
        mockToken.transfer(address(distributor), 10 ether);

        // Alice claims the rewards
        vm.prank(alice);

        assertEq(mockToken.balanceOf(alice), 0, "Alice should have 0 token balance");

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1 ether;
        amounts[1] = 1 ether;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);
        proofs[1] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        distributor.claimRewards(address(mockToken), pubkeyHashes, amounts, proofs);

        assertEq(mockToken.balanceOf(alice), 2 ether, "Alice should have received 2 tokens");
        assertEq(mockToken.balanceOf(bob), 0 ether, "Bob should have received 0 tokens");

        vm.expectRevert(IUnifiRewardsDistributor.NothingToClaim.selector);
        distributor.claimRewards(address(mockToken), pubkeyHashes, amounts, proofs);
    }

    function test_ClaimRewards_cummulative() public {
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32[] memory pubkeyHashes = new bytes32[](2);
        pubkeyHashes[0] = distributor.getBlsPubkeyHash(alicePublicKey);
        pubkeyHashes[1] = distributor.getBlsPubkeyHash(bobPublicKey);

        // Since we're using hardcoded values, we need to recreate those values with our
        // new implementation that includes token addresses.
        // For testing purposes, we'll generate a new Merkle tree here
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](2);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[0], token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[1], token: NATIVE_TOKEN, amount: 1 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);
        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time so that the pending root becomes active
        vm.warp(block.timestamp + 8 days);

        // Set claimer for Alice
        test_registerClaimer();

        _registerClaimer(bobValidatorPrivateKey, bob, alice);

        // Deal some ETH to the distributor, so that it has some balance
        vm.deal(address(distributor), 100 ether);

        assertEq(alice.balance, 0, "Alice should have 0 balance");

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1 ether;
        amounts[1] = 1 ether;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);
        proofs[1] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        distributor.claimRewards(NATIVE_TOKEN, pubkeyHashes, amounts, proofs);

        assertEq(
            distributor.validatorClaimedAmount(NATIVE_TOKEN, pubkeyHashes[0]),
            1 ether,
            "claimed amount should be 1 ether for validator 1"
        );
        assertEq(
            distributor.validatorClaimedAmount(NATIVE_TOKEN, pubkeyHashes[1]),
            1 ether,
            "claimed amount should be 1 ether for validator 2"
        );

        assertEq(alice.balance, 2 ether, "Alice should have received 2 ether");
        assertEq(bob.balance, 0 ether, "Bob should have received 0 ether");

        // New Merkle root contains the cumulative rewards for the validators
        MerkleProofData[] memory newMerkleProofDatas = new MerkleProofData[](2);
        // Now we create a new merkle root with more rewards, 5 eth for the first validator and 10 eth for the second validator
        newMerkleProofDatas[0] =
            MerkleProofData({ blsPubkeyHash: pubkeyHashes[0], token: NATIVE_TOKEN, amount: 5 ether });
        newMerkleProofDatas[1] =
            MerkleProofData({ blsPubkeyHash: pubkeyHashes[1], token: NATIVE_TOKEN, amount: 10 ether });

        merkleRoot = _buildMerkleProof(newMerkleProofDatas);
        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time so that the pending root becomes active
        vm.warp(block.timestamp + 8 days);

        uint256[] memory newAmounts = new uint256[](2);
        newAmounts[0] = 5 ether;
        newAmounts[1] = 10 ether;

        bytes32[][] memory newProofs = new bytes32[][](2);
        newProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);
        newProofs[1] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        distributor.claimRewards(NATIVE_TOKEN, pubkeyHashes, newAmounts, newProofs);

        assertEq(
            distributor.validatorClaimedAmount(NATIVE_TOKEN, pubkeyHashes[0]),
            5 ether,
            "claimed amount should be 5 ether for validator 1"
        );
        assertEq(
            distributor.validatorClaimedAmount(NATIVE_TOKEN, pubkeyHashes[1]),
            10 ether,
            "claimed amount should be 10 ether for validator 2"
        );

        // In the first claiming interval Alice claimed 2(1 + 1) ETH, and in the second one, she claimed (4 + 9), thats a total of 15 ether
        assertEq(alice.balance, 15 ether, "Alice should have received 15 ether");
        assertEq(bob.balance, 0 ether, "Bob should have received 0 ether");
    }

    function test_revertClaimerNotSet() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: bytes32("alice"), token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), token: NATIVE_TOKEN, amount: 2 ether });
        merkleProofDatas[2] =
            MerkleProofData({ blsPubkeyHash: bytes32("charlie"), token: NATIVE_TOKEN, amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        // Empty proof, doesn't matter
        bytes32[][] memory aliceProofs = new bytes32[][](1);

        bytes32[] memory alicePubkeyHashes = new bytes32[](1);
        alicePubkeyHashes[0] = bytes32("alice");

        uint256[] memory aliceAmounts = new uint256[](1);
        aliceAmounts[0] = 1 ether;

        vm.expectRevert(IUnifiRewardsDistributor.ClaimerNotSet.selector);
        distributor.claimRewards(NATIVE_TOKEN, alicePubkeyHashes, aliceAmounts, aliceProofs);
    }

    function testRevert_claimRewards_invalidLengths() public {
        bytes32[][] memory aliceProofs = new bytes32[][](2);
        bytes32[] memory alicePubkeyHashes = new bytes32[](1);
        uint256[] memory aliceAmounts = new uint256[](1);

        vm.expectRevert(IUnifiRewardsDistributor.InvalidInput.selector);
        distributor.claimRewards(NATIVE_TOKEN, alicePubkeyHashes, aliceAmounts, aliceProofs);
    }

    function test_revertInvalidProof() public {
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        bytes32 alicePubkeyHash = distributor.getBlsPubkeyHash(alicePublicKey);

        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: alicePubkeyHash, token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), token: NATIVE_TOKEN, amount: 2 ether });
        merkleProofDatas[2] =
            MerkleProofData({ blsPubkeyHash: bytes32("charlie"), token: NATIVE_TOKEN, amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setNewMerkleRoot(merkleRoot);

        vm.warp(block.timestamp + 8 days);

        // Set claimer for Alice
        test_registerClaimer();

        // Empty proof, doesn't matter
        bytes32[][] memory aliceProofs = new bytes32[][](1);
        bytes32[] memory alicePubkeyHashes = new bytes32[](1);
        alicePubkeyHashes[0] = alicePubkeyHash;

        uint256[] memory aliceAmounts = new uint256[](1);
        aliceAmounts[0] = 1 ether;

        vm.expectRevert(IUnifiRewardsDistributor.InvalidProof.selector);
        distributor.claimRewards(NATIVE_TOKEN, alicePubkeyHashes, aliceAmounts, aliceProofs);
    }

    function test_rescueFunds() public {
        address payable recipient = payable(makeAddr("recipient"));
        vm.deal(address(distributor), 5 ether);

        assertEq(address(recipient).balance, 0, "Recipient should have 0 balance");
        assertEq(address(distributor).balance, 5 ether, "Distributor should have 5 ETH");

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.RescuedFunds(NATIVE_TOKEN, recipient, 3 ether);
        distributor.rescueFunds(NATIVE_TOKEN, recipient, 3 ether);

        assertEq(address(recipient).balance, 3 ether, "Recipient should have received 3 ETH");
        assertEq(address(distributor).balance, 2 ether, "Distributor should have 2 ETH left");
    }

    function test_rescueTokens() public {
        address recipient = makeAddr("recipient");
        mockToken.transfer(address(distributor), 5 ether);

        assertEq(mockToken.balanceOf(recipient), 0, "Recipient should have 0 token balance");
        assertEq(mockToken.balanceOf(address(distributor)), 5 ether, "Distributor should have 5 tokens");

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.RescuedFunds(address(mockToken), recipient, 3 ether);
        distributor.rescueFunds(address(mockToken), recipient, 3 ether);

        assertEq(mockToken.balanceOf(recipient), 3 ether, "Recipient should have received 3 tokens");
        assertEq(mockToken.balanceOf(address(distributor)), 2 ether, "Distributor should have 2 tokens left");
    }

    function test_cancelPendingMerkleRoot() public {
        bytes32 newMerkleRoot = keccak256("new merkle root");

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.MerkleRootSet(newMerkleRoot, block.timestamp + 7 days);
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

        IUnifiRewardsDistributor.PubkeyRegistrationParams[] memory paramsArray =
            new IUnifiRewardsDistributor.PubkeyRegistrationParams[](1);
        paramsArray[0] = params;

        // Execute registration
        vm.prank(alice);
        distributor.registerClaimer(alice, paramsArray);

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

        IUnifiRewardsDistributor.PubkeyRegistrationParams[] memory paramsArray =
            new IUnifiRewardsDistributor.PubkeyRegistrationParams[](1);
        paramsArray[0] = params;

        // Execute registration
        vm.prank(caller);
        distributor.registerClaimer(claimer, paramsArray);

        // Verify registration
        assertEq(distributor.getClaimer(pubkeyHash), claimer);
    }

    function test_revertRegisterClaimer_badSignature() public {
        BLS.G1Point memory publicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G2Point memory signature;

        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: signature, publicKey: publicKey });

        IUnifiRewardsDistributor.PubkeyRegistrationParams[] memory paramsArray =
            new IUnifiRewardsDistributor.PubkeyRegistrationParams[](1);
        paramsArray[0] = params;

        vm.expectRevert(IUnifiRewardsDistributor.BadBLSSignature.selector);
        distributor.registerClaimer(alice, paramsArray);
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

    function test_basicReentrancyProtection() public {
        // Setup for a basic reentrancy test
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32 alicePubkeyHash = distributor.getBlsPubkeyHash(alicePublicKey);
        bytes32 bobPubkeyHash = distributor.getBlsPubkeyHash(bobPublicKey);

        // Test basic claim with ETH
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](2);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: alicePubkeyHash, token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bobPubkeyHash, token: NATIVE_TOKEN, amount: 2 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        // Set the merkle root
        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time to make the merkle root active
        vm.warp(block.timestamp + 8 days);

        // Deal ETH to the distributor
        vm.deal(address(distributor), 5 ether);

        // Register attacker as claimer for the first validator
        _registerClaimer(aliceValidatorPrivateKey, alice, address(attacker));

        // Setup attack parameters
        bytes32[] memory pubkeyHashes = new bytes32[](1);
        pubkeyHashes[0] = alicePubkeyHash;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);

        // Prepare attacker
        attacker.setAttackParams(NATIVE_TOKEN, pubkeyHashes, amounts, proofs);

        // Record balances before attack
        uint256 initialDistributorBalance = address(distributor).balance;
        uint256 initialAttackerBalance = address(attacker).balance;

        // Execute attack
        attacker.attack();

        // Check balances after attack
        uint256 finalDistributorBalance = address(distributor).balance;
        uint256 finalAttackerBalance = address(attacker).balance;

        // Verify only the correct amount was transferred (1 ETH)
        assertEq(finalAttackerBalance - initialAttackerBalance, 1 ether, "Attacker should only receive 1 ETH");
        assertEq(initialDistributorBalance - finalDistributorBalance, 1 ether, "Distributor should only send 1 ETH");

        // Try to claim again - should fail
        vm.expectRevert(IUnifiRewardsDistributor.NothingToClaim.selector);
        vm.prank(address(attacker));
        distributor.claimRewards(NATIVE_TOKEN, pubkeyHashes, amounts, proofs);
    }

    function test_tokenReentrancyProtection() public {
        // Setup for token-based reentrancy test
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32 alicePubkeyHash = distributor.getBlsPubkeyHash(alicePublicKey);
        bytes32 bobPubkeyHash = distributor.getBlsPubkeyHash(bobPublicKey);

        // Create merkle proof for token rewards
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](2);
        merkleProofDatas[0] =
            MerkleProofData({ blsPubkeyHash: alicePubkeyHash, token: address(mockToken), amount: 2 ether });
        merkleProofDatas[1] =
            MerkleProofData({ blsPubkeyHash: bobPubkeyHash, token: address(mockToken), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        // Set the merkle root
        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time to make the merkle root active
        vm.warp(block.timestamp + 8 days);

        // Send tokens to the distributor
        mockToken.transfer(address(distributor), 10 ether);

        // Register attacker as claimer for the first validator
        _registerClaimer(aliceValidatorPrivateKey, alice, address(attacker));

        // Setup cross-token attack parameters
        bytes32[] memory tokenPubkeyHashes = new bytes32[](1);
        tokenPubkeyHashes[0] = alicePubkeyHash;

        uint256[] memory tokenAmounts = new uint256[](1);
        tokenAmounts[0] = 2 ether;

        bytes32[][] memory tokenProofs = new bytes32[][](1);
        tokenProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);

        // Setup a second attacker with the same parameters to try to re-enter
        attacker.setAttackParams(address(mockToken), tokenPubkeyHashes, tokenAmounts, tokenProofs);
        attacker.setCrossTokenAttackParams(address(mockToken), tokenPubkeyHashes, tokenAmounts, tokenProofs);

        // Record balances before attack
        uint256 initialDistributorTokenBalance = mockToken.balanceOf(address(distributor));
        uint256 initialAttackerTokenBalance = mockToken.balanceOf(address(attacker));

        // Execute attack
        attacker.attack();

        // Check balances after attack
        uint256 finalDistributorTokenBalance = mockToken.balanceOf(address(distributor));
        uint256 finalAttackerTokenBalance = mockToken.balanceOf(address(attacker));

        // Verify only the correct amount of tokens was transferred
        assertEq(
            finalAttackerTokenBalance - initialAttackerTokenBalance, 2 ether, "Attacker should only receive 2 tokens"
        );
        assertEq(
            initialDistributorTokenBalance - finalDistributorTokenBalance,
            2 ether,
            "Distributor should only send 2 tokens"
        );

        // Try to claim again - should fail
        vm.expectRevert(IUnifiRewardsDistributor.NothingToClaim.selector);
        vm.prank(address(attacker));
        distributor.claimRewards(address(mockToken), tokenPubkeyHashes, tokenAmounts, tokenProofs);
    }

    function test_crossTokenReentrancyProtection() public {
        // Setup for cross-token reentrancy test (ETH to tokens)
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32 alicePubkeyHash = distributor.getBlsPubkeyHash(alicePublicKey);
        bytes32 bobPubkeyHash = distributor.getBlsPubkeyHash(bobPublicKey);

        // Create merkle proof for both ETH and token rewards
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: alicePubkeyHash, token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] =
            MerkleProofData({ blsPubkeyHash: alicePubkeyHash, token: address(mockToken), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bobPubkeyHash, token: NATIVE_TOKEN, amount: 0.5 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        // Set the merkle root
        distributor.setNewMerkleRoot(merkleRoot);

        // Advance time to make the merkle root active
        vm.warp(block.timestamp + 8 days);

        // Setup funds for distributor
        vm.deal(address(distributor), 5 ether);
        mockToken.transfer(address(distributor), 10 ether);

        // Register attacker as claimer for the validator
        _registerClaimer(aliceValidatorPrivateKey, alice, address(attacker));

        // Setup ETH claim parameters
        bytes32[] memory ethPubkeyHashes = new bytes32[](1);
        ethPubkeyHashes[0] = alicePubkeyHash;

        uint256[] memory ethAmounts = new uint256[](1);
        ethAmounts[0] = 1 ether;

        bytes32[][] memory ethProofs = new bytes32[][](1);
        ethProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);

        // Setup token claim parameters
        bytes32[] memory tokenPubkeyHashes = new bytes32[](1);
        tokenPubkeyHashes[0] = alicePubkeyHash;

        uint256[] memory tokenAmounts = new uint256[](1);
        tokenAmounts[0] = 2 ether;

        bytes32[][] memory tokenProofs = new bytes32[][](1);
        tokenProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        // Setup the attack parameters
        attacker.setAttackParams(NATIVE_TOKEN, ethPubkeyHashes, ethAmounts, ethProofs);
        attacker.setCrossTokenAttackParams(address(mockToken), tokenPubkeyHashes, tokenAmounts, tokenProofs);

        // Record balances before attack
        uint256 initialDistributorEthBalance = address(distributor).balance;
        uint256 initialDistributorTokenBalance = mockToken.balanceOf(address(distributor));
        uint256 initialAttackerEthBalance = address(attacker).balance;
        uint256 initialAttackerTokenBalance = mockToken.balanceOf(address(attacker));

        // Execute attack - with nonReentrant modifier, token claim during reentrancy should fail
        attacker.attack();

        // Check final balances after attack
        uint256 finalDistributorEthBalance = address(distributor).balance;
        uint256 finalDistributorTokenBalance = mockToken.balanceOf(address(distributor));
        uint256 finalAttackerEthBalance = address(attacker).balance;
        uint256 finalAttackerTokenBalance = mockToken.balanceOf(address(attacker));

        // Verify ETH was transferred
        assertEq(finalAttackerEthBalance - initialAttackerEthBalance, 1 ether, "Attacker should receive 1 ETH");
        assertEq(initialDistributorEthBalance - finalDistributorEthBalance, 1 ether, "Distributor should send 1 ETH");

        // The token claim during reentrancy should have failed due to nonReentrant modifier
        assertEq(attacker.tokenClaimSucceeded(), false, "Cross-token reentrancy should be prevented");

        // And tokens should NOT have been transferred during the reentrancy attack
        assertEq(
            finalAttackerTokenBalance - initialAttackerTokenBalance,
            0,
            "Attacker should not receive tokens during reentrancy"
        );
        assertEq(
            initialDistributorTokenBalance,
            finalDistributorTokenBalance,
            "Distributor token balance should not change during reentrancy"
        );

        // Now claim tokens legitimately after the ETH claim
        vm.prank(address(attacker));
        distributor.claimRewards(address(mockToken), tokenPubkeyHashes, tokenAmounts, tokenProofs);

        // Check final token balances after legitimate claim
        finalAttackerTokenBalance = mockToken.balanceOf(address(attacker));
        finalDistributorTokenBalance = mockToken.balanceOf(address(distributor));

        // Verify tokens were transferred in the legitimate claim
        assertEq(
            finalAttackerTokenBalance - initialAttackerTokenBalance,
            2 ether,
            "Attacker should receive 2 tokens after legitimate claim"
        );
        assertEq(
            initialDistributorTokenBalance - finalDistributorTokenBalance,
            2 ether,
            "Distributor should send 2 tokens after legitimate claim"
        );
    }

    function test_revertClaimRewards_zeroToken() public {
        bytes32[] memory pubkeyHashes = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        bytes32[][] memory proofs = new bytes32[][](1);

        vm.expectRevert(IUnifiRewardsDistributor.InvalidInput.selector);
        distributor.claimRewards(address(0), pubkeyHashes, amounts, proofs);
    }

    function test_revertClaimRewards_differentClaimers() public {
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32[] memory pubkeyHashes = new bytes32[](2);
        pubkeyHashes[0] = distributor.getBlsPubkeyHash(alicePublicKey);
        pubkeyHashes[1] = distributor.getBlsPubkeyHash(bobPublicKey);

        // Register different claimers for each validator
        _registerClaimer(aliceValidatorPrivateKey, alice, alice);
        _registerClaimer(bobValidatorPrivateKey, bob, bob);

        // Build merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](2);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[0], token: NATIVE_TOKEN, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: pubkeyHashes[1], token: NATIVE_TOKEN, amount: 1 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);
        distributor.setNewMerkleRoot(merkleRoot);
        vm.warp(block.timestamp + 8 days);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1 ether;
        amounts[1] = 1 ether;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);
        proofs[1] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 1);

        vm.expectRevert(IUnifiRewardsDistributor.InvalidInput.selector);
        distributor.claimRewards(NATIVE_TOKEN, pubkeyHashes, amounts, proofs);
    }

    function test_setNewMerkleRoot_activatePending() public {
        bytes32 firstRoot = keccak256("first root");
        bytes32 secondRoot = keccak256("second root");

        // Set first root
        distributor.setNewMerkleRoot(firstRoot);

        // Advance time past activation
        vm.warp(block.timestamp + 8 days);

        // Set second root - this should activate the first root
        distributor.setNewMerkleRoot(secondRoot);

        assertEq(distributor.getMerkleRoot(), firstRoot, "First root should be active");
    }

    function test_cancelPendingMerkleRoot_noPending() public {
        vm.expectRevert(IUnifiRewardsDistributor.NoPendingMerkleRoot.selector);
        distributor.cancelPendingMerkleRoot();
    }

    function test_registerClaimer_multipleValidators() public {
        // Generate public keys for two validators
        BLS.G1Point memory alicePublicKey = _blsg1mul(G1_GENERATOR(), bytes32(aliceValidatorPrivateKey));
        BLS.G1Point memory bobPublicKey = _blsg1mul(G1_GENERATOR(), bytes32(bobValidatorPrivateKey));

        bytes32 alicePubkeyHash = distributor.getBlsPubkeyHash(alicePublicKey);
        bytes32 bobPubkeyHash = distributor.getBlsPubkeyHash(bobPublicKey);

        // Create message hashes
        bytes memory aliceMessage = distributor.getMessageHash(alice, alicePubkeyHash);
        bytes memory bobMessage = distributor.getMessageHash(alice, bobPubkeyHash);

        BLS.G2Point memory aliceMessagePoint = BLS.hashToG2(aliceMessage);
        BLS.G2Point memory bobMessagePoint = BLS.hashToG2(bobMessage);

        // Create signatures
        BLS.G2Point memory aliceSignature = _blsg2mul(aliceMessagePoint, bytes32(aliceValidatorPrivateKey));
        BLS.G2Point memory bobSignature = _blsg2mul(bobMessagePoint, bytes32(bobValidatorPrivateKey));

        // Build params array
        IUnifiRewardsDistributor.PubkeyRegistrationParams[] memory params =
            new IUnifiRewardsDistributor.PubkeyRegistrationParams[](2);

        params[0] =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: aliceSignature, publicKey: alicePublicKey });

        params[1] =
            IUnifiRewardsDistributor.PubkeyRegistrationParams({ signature: bobSignature, publicKey: bobPublicKey });

        // Register both validators
        vm.prank(alice);
        distributor.registerClaimer(alice, params);

        // Verify both registrations
        assertEq(distributor.getClaimer(alicePubkeyHash), alice, "Alice's validator should be registered");
        assertEq(distributor.getClaimer(bobPubkeyHash), alice, "Bob's validator should be registered");
    }

    function test_rescueFunds_zeroAmount() public {
        address recipient = makeAddr("recipient");
        vm.expectRevert(IUnifiRewardsDistributor.InvalidInput.selector);
        distributor.rescueFunds(NATIVE_TOKEN, recipient, 0);
    }

    function test_rescueFunds_zeroRecipient() public {
        vm.expectRevert(IUnifiRewardsDistributor.InvalidInput.selector);
        distributor.rescueFunds(NATIVE_TOKEN, address(0), 1 ether);
    }

    // Some Lib Tests

    function test_BLS_add() public view {
        // Test G1 point addition
        BLS.G1Point memory point1 = G1_GENERATOR();
        BLS.G1Point memory point2 = G1_GENERATOR();
        BLS.G1Point memory result = BLS.add(point1, point2);

        // Verify result is not zero
        assertTrue(
            result.x_a != bytes32(0) || result.x_b != bytes32(0) || result.y_a != bytes32(0) || result.y_b != bytes32(0),
            "Result should not be zero point"
        );

        // Test G2 point addition using hashToG2 to get valid G2 points
        bytes memory message1 = "test message 1";
        bytes memory message2 = "test message 2";

        BLS.G2Point memory g2Point1 = BLS.hashToG2(message1);
        BLS.G2Point memory g2Point2 = BLS.hashToG2(message2);

        BLS.G2Point memory g2Result = BLS.add(g2Point1, g2Point2);

        // Verify result is not zero
        assertTrue(
            g2Result.x_c0_a != bytes32(0) || g2Result.x_c0_b != bytes32(0) || g2Result.x_c1_a != bytes32(0)
                || g2Result.x_c1_b != bytes32(0) || g2Result.y_c0_a != bytes32(0) || g2Result.y_c0_b != bytes32(0)
                || g2Result.y_c1_a != bytes32(0) || g2Result.y_c1_b != bytes32(0),
            "G2 result should not be zero point"
        );
    }

    function test_BLS_toG1() public view {
        // Test converting a field element to G1
        BLS.Fp memory element = BLS.Fp({ a: bytes32(uint256(1)), b: bytes32(uint256(2)) });

        BLS.G1Point memory result = BLS.toG1(element);

        // Verify result is not zero
        assertTrue(
            result.x_a != bytes32(0) || result.x_b != bytes32(0) || result.y_a != bytes32(0) || result.y_b != bytes32(0),
            "Result should not be zero point"
        );
    }

    function test_BLS_toG2() public view {
        // Test converting a field element to G2
        BLS.Fp2 memory element = BLS.Fp2({
            c0_a: bytes32(uint256(1)),
            c0_b: bytes32(uint256(2)),
            c1_a: bytes32(uint256(3)),
            c1_b: bytes32(uint256(4))
        });

        BLS.G2Point memory result = BLS.toG2(element);

        // Verify result is not zero
        assertTrue(
            result.x_c0_a != bytes32(0) || result.x_c0_b != bytes32(0) || result.x_c1_a != bytes32(0)
                || result.x_c1_b != bytes32(0) || result.y_c0_a != bytes32(0) || result.y_c0_b != bytes32(0)
                || result.y_c1_a != bytes32(0) || result.y_c1_b != bytes32(0),
            "Result should not be zero point"
        );
    }
}
