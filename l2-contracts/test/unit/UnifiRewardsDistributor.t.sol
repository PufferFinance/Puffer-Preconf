// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UnifiRewardsDistributor } from "../../src/UnifiRewardsDistributor.sol";
import { IUnifiRewardsDistributor } from "../../src/interfaces/IUnifiRewardsDistributor.sol";
import { BN254 } from "../../src/library/BN254.sol";
import { UnitTestHelper } from "../helpers/UnitTestHelper.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Merkle } from "murky/Merkle.sol";

contract UnifiRewardsDistributorTest is UnitTestHelper {
    struct MerkleProofData {
        bytes32 blsPubkeyHash;
        uint256 amount;
    }

    using BN254 for BN254.G1Point;
    using BN254 for BN254.G2Point;
    using Strings for uint256;

    UnifiRewardsDistributor internal distributor;
    Merkle internal rewardsMerkleProof;
    bytes32[] internal rewardsMerkleProofData;

    // Dummy BLS private key (never use in production!)
    uint256 aliceValidatorPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    bytes32 aliceValidatorPubkeyHash = hex"349f9310273a8c4383749e137887aa02e8f1fada8f181449796da01aec23455a";
    address alice = makeAddr("alice");

    function setUp() public override {
        distributor = new UnifiRewardsDistributor();
    }

    // TEST HELPERS

    function _generateBlsPubkeyParams(uint256 privKey)
        internal
        returns (IUnifiRewardsDistributor.PubkeyRegistrationParams memory)
    {
        IUnifiRewardsDistributor.PubkeyRegistrationParams memory pubkey;
        pubkey.pubkeyG1 = BN254.generatorG1().scalar_mul(privKey);
        pubkey.pubkeyG2 = _mulGo(privKey);
        return pubkey;
    }

    function _mulGo(uint256 x) internal returns (BN254.G2Point memory g2Point) {
        string[] memory inputs = new string[](3);
        inputs[0] = "./test/helpers/go2mul-mac"; // lib/eigenlayer-middleware/test/ffi/go/g2mul.go binary
        // inputs[0] = "./test/helpers/go2mul"; // lib/eigenlayer-middleware/test/ffi/go/g2mul.go binary
        inputs[1] = x.toString();

        inputs[2] = "1";
        bytes memory res = vm.ffi(inputs);
        g2Point.X[1] = abi.decode(res, (uint256));

        inputs[2] = "2";
        res = vm.ffi(inputs);
        g2Point.X[0] = abi.decode(res, (uint256));

        inputs[2] = "3";
        res = vm.ffi(inputs);
        g2Point.Y[1] = abi.decode(res, (uint256));

        inputs[2] = "4";
        res = vm.ffi(inputs);
        g2Point.Y[0] = abi.decode(res, (uint256));
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
        assertEq(
            distributor.getDomainSeparator(),
            hex"d32f061b01d16855195c8960273642ffce14fcb5b99af48907b633d4a80d61ed",
            "Domain separator should be correct"
        );
        assertEq(
            distributor.getClaimerTypedDataHash(bytes32(0), address(0)),
            hex"cddef5d09da988d31f9b9a30a404ea35246ee28c4aaa228ac5ea268d81091fba",
            "Claimer typed data hash should be correct"
        );
    }

    function test_setMerkleRoot() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: bytes32("alice"), amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        vm.expectEmit(true, true, true, true);
        emit IUnifiRewardsDistributor.MerkleRootSet(merkleRoot);
        distributor.setMerkleRoot(merkleRoot);
    }

    function test_setMerkleRoot_zeroRoot() public {
        vm.expectRevert(IUnifiRewardsDistributor.MerkleRootCannotBeZero.selector);
        distributor.setMerkleRoot(bytes32(0));
    }

    function test_ClaimRewards() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: aliceValidatorPubkeyHash, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setMerkleRoot(merkleRoot);

        // Set claimer for Alice
        test_registerClaimer();

        // Deal some ETH to the distributor, so that it has some balance
        vm.deal(address(distributor), 10 ether);

        // Alice claims the rewards
        vm.prank(alice);

        assertEq(alice.balance, 0, "Alice should have 0 balance");

        bytes32[][] memory aliceProofs = new bytes32[][](1);
        aliceProofs[0] = rewardsMerkleProof.getProof(rewardsMerkleProofData, 0);

        distributor.claimRewards(aliceValidatorPubkeyHash, 1 ether, aliceProofs[0]);

        assertEq(alice.balance, 1 ether, "Alice should have received 1 ether");

        vm.expectRevert(IUnifiRewardsDistributor.NothingToClaim.selector);
        distributor.claimRewards(aliceValidatorPubkeyHash, 1 ether, aliceProofs[0]);
    }

    function test_revertClaimerNotSet() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: aliceValidatorPubkeyHash, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setMerkleRoot(merkleRoot);

        // Empty proof, doesn't matter
        bytes32[][] memory aliceProofs = new bytes32[][](1);

        vm.expectRevert(IUnifiRewardsDistributor.ClaimerNotSet.selector);
        distributor.claimRewards(aliceValidatorPubkeyHash, 1 ether, aliceProofs[0]);
    }

    function test_revertInvalidProof() public {
        // Build a merkle proof
        MerkleProofData[] memory merkleProofDatas = new MerkleProofData[](3);
        merkleProofDatas[0] = MerkleProofData({ blsPubkeyHash: aliceValidatorPubkeyHash, amount: 1 ether });
        merkleProofDatas[1] = MerkleProofData({ blsPubkeyHash: bytes32("bob"), amount: 2 ether });
        merkleProofDatas[2] = MerkleProofData({ blsPubkeyHash: bytes32("charlie"), amount: 3 ether });

        bytes32 merkleRoot = _buildMerkleProof(merkleProofDatas);

        distributor.setMerkleRoot(merkleRoot);

        // Set claimer for Alice
        test_registerClaimer();

        // Empty proof, doesn't matter
        bytes32[][] memory aliceProofs = new bytes32[][](1);

        vm.expectRevert(IUnifiRewardsDistributor.InvalidProof.selector);
        distributor.claimRewards(aliceValidatorPubkeyHash, 1 ether, aliceProofs[0]);
    }

    function test_registerClaimer() public {
        // Generate public keys
        BN254.G1Point memory pubkeyG1 = BN254.generatorG1().scalar_mul(aliceValidatorPrivateKey);
        BN254.G2Point memory pubkeyG2 = _mulGo(aliceValidatorPrivateKey);

        // Create message hash
        bytes32 pubkeyHash = distributor.getBlsPubkeyHash(pubkeyG1);

        BN254.G1Point memory messageHash = distributor.getClaimerMessageHash(pubkeyHash, alice);

        // Create signature (H(m) * privateKey)
        BN254.G1Point memory signature = messageHash.scalar_mul(aliceValidatorPrivateKey);

        // Build params
        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params = IUnifiRewardsDistributor
            .PubkeyRegistrationParams({ pubkeyRegistrationSignature: signature, pubkeyG1: pubkeyG1, pubkeyG2: pubkeyG2 });

        // Execute registration
        vm.prank(alice);
        distributor.registerClaimer(alice, params);

        // Verify registration
        assertEq(distributor.getClaimer(pubkeyHash), alice);
    }

    function test_revertRegisterClaimer_badSignature() public {
        BN254.G1Point memory pubkeyG1 = BN254.generatorG1().scalar_mul(aliceValidatorPrivateKey);
        BN254.G2Point memory pubkeyG2 = _mulGo(aliceValidatorPrivateKey);
        BN254.G1Point memory signature;

        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params = IUnifiRewardsDistributor
            .PubkeyRegistrationParams({ pubkeyRegistrationSignature: signature, pubkeyG1: pubkeyG1, pubkeyG2: pubkeyG2 });

        vm.expectRevert(IUnifiRewardsDistributor.BadBLSSignature.selector);
        distributor.registerClaimer(alice, params);
    }
}
