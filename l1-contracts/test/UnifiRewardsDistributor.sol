// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BN254 } from "../src/library/BN254.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { UnitTestHelper } from "../test/helpers/UnitTestHelper.sol";
import { IUnifiRewardsDistributor } from "../src/interfaces/IUnifiRewardsDistributor.sol";
import { UnifiRewardsDistributor } from "../src/UnifiRewardsDistributor.sol";

contract UnifiRewardsDistributorTest is UnitTestHelper {
    using BN254 for BN254.G1Point;
    using BN254 for BN254.G2Point;
    using Strings for uint256;

    UnifiRewardsDistributor internal distributor;

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

    function test_setClaimer() public {
        // Dummy BLS private key (never use in production!)
        uint256 privateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;

        // Generate public keys
        BN254.G1Point memory pubkeyG1 = BN254.generatorG1().scalar_mul(privateKey);
        BN254.G2Point memory pubkeyG2 = _mulGo(privateKey);

        // Create message hash
        bytes32 pubkeyHash = distributor.getBlsPubkeyHash(pubkeyG1);

        BN254.G1Point memory messageHash = distributor.getClaimerMessageHash(pubkeyHash, alice);

        // Create signature (H(m) * privateKey)
        BN254.G1Point memory signature = messageHash.scalar_mul(privateKey);

        // Build params
        IUnifiRewardsDistributor.PubkeyRegistrationParams memory params = IUnifiRewardsDistributor
            .PubkeyRegistrationParams({ pubkeyRegistrationSignature: signature, pubkeyG1: pubkeyG1, pubkeyG2: pubkeyG2 });

        // Execute registration
        vm.prank(DAO);
        distributor.registerClaimer(alice, params);

        // Verify registration
        assertEq(distributor.getClaimer(pubkeyHash), alice);
    }
}
