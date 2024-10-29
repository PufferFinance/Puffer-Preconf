// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/UniFiAVSManager.sol";
import "../src/interfaces/IUniFiAVSManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import "../src/structs/ValidatorData.sol";
import "../src/structs/OperatorData.sol";
import "./mocks/MockEigenPodManager.sol";
import "./mocks/MockDelegationManager.sol";
import "./mocks/MockAVSDirectory.sol";
import "eigenlayer-middleware/libraries/BN254.sol";
import "eigenlayer-middleware/interfaces/IBLSApkRegistry.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { UnitTestHelper } from "../test/helpers/UnitTestHelper.sol";
import { BeaconProofs } from "./fixtures/BeaconProofs.sol";

contract UniFiAVSManagerTest is UnitTestHelper {
    using BN254 for BN254.G1Point;
    using Strings for uint256;

    address constant BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

    bytes delegatePubKey = abi.encodePacked(uint256(1337));

    // TEST HELPERS

    function _generateBlsPubkeyParams(uint256 privKey)
        internal
        returns (IBLSApkRegistry.PubkeyRegistrationParams memory)
    {
        IBLSApkRegistry.PubkeyRegistrationParams memory pubkey;
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

    function _getValidatorSignature(
        uint256 validatorPrivateKey,
        uint64 validatorIndex,
        address operator,
        uint256 salt,
        uint256 expiry
    ) internal returns (BN254.G1Point memory registrationSignature, bytes32 pubkeyHash) {
        // Generate BLS key pair
        IBLSApkRegistry.PubkeyRegistrationParams memory blsKeyPair = _generateBlsPubkeyParams(validatorPrivateKey);

        // Create ValidatorRegistrationParams
        ValidatorRegistrationParams memory params;

        params.salt = uint64(salt);
        params.expiry = expiry;
        params.index = validatorIndex;

        // Generate a valid signature
        BN254.G1Point memory messagePoint =
            avsManager.blsMessageHash(operator, params.salt, params.expiry, params.index);

        registrationSignature = messagePoint.scalar_mul(validatorPrivateKey);
        pubkeyHash = BLSSignatureCheckerLib.hashG1Point(blsKeyPair.pubkeyG1);

        return (registrationSignature, pubkeyHash);
    }

    // With ECDSA key, he sign the hash confirming that the operator wants to be registered to a certain restaking service
    function _getOperatorSignature(
        uint256 _operatorPrivateKey,
        address _operator,
        address avs,
        bytes32 salt,
        uint256 expiry
    ) internal view returns (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) {
        operatorSignature.expiry = expiry;
        operatorSignature.salt = salt;
        {
            digestHash = mockAVSDirectory.calculateOperatorAVSRegistrationDigestHash(operator, avs, salt, expiry);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(_operatorPrivateKey, digestHash);
            operatorSignature.signature = abi.encodePacked(r, s, v);
        }
        return (digestHash, operatorSignature);
    }

    function _setupOperator() internal {
        mockDelegationManager.setOperator(operator, true);
        mockEigenPodManager.createPod(podOwner);
        mockDelegationManager.setDelegation(podOwner, operator);
    }

    function _registerOperatorParams(bytes32 salt, uint256 expiry)
        internal
        returns (ISignatureUtils.SignatureWithSaltAndExpiry memory)
    {
        (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) =
            _getOperatorSignature(operatorPrivateKey, operator, address(avsManager), salt, expiry);

        return operatorSignature;
    }

    function _registerOperator() public {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _registerOperatorParams({ salt: bytes32(uint256(1)), expiry: uint256(block.timestamp + 1 days) });

        vm.prank(operator);
        avsManager.registerOperator(operatorSignature);

        _setOperatorCommitment(operator, delegatePubKey, 0);
    }

    function _setOperatorCommitment(address _operator, bytes memory _delegateKey, uint256 _chainIDBitMap) internal {
        vm.prank(_operator);
        avsManager.setOperatorCommitment(
            OperatorCommitment({ delegateKey: _delegateKey, chainIDBitMap: _chainIDBitMap })
        );

        vm.roll(block.number + avsManager.getDeregistrationDelay());

        vm.prank(_operator);
        avsManager.updateOperatorCommitment();
    }

    // BEGIN TESTS

    function testInitialize() public {
        // todo add appropriate initialization checks here
        assertTrue(address(avsManager) != address(0));
    }

    function test_registerOperatorHelper() public {
        _setupOperator();
        assertFalse(mockAVSDirectory.isOperatorRegistered(operator));
        _registerOperator();
        assertTrue(mockAVSDirectory.isOperatorRegistered(operator));

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey);
        assertEq(operatorData.commitment.chainIDBitMap, 0);
        assertEq(operatorData.pendingCommitment.delegateKey, "");
        assertEq(operatorData.pendingCommitment.chainIDBitMap, 0);
    }

    function testRegisterOperator() public {
        _setupOperator();
        assertFalse(mockAVSDirectory.isOperatorRegistered(operator));

        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _registerOperatorParams({ salt: bytes32(uint256(1)), expiry: uint256(block.timestamp + 1 days) });

        vm.expectEmit(true, false, false, false);
        emit IUniFiAVSManager.OperatorRegistered(operator);

        vm.prank(operator);
        avsManager.registerOperator(operatorSignature);

        assertTrue(mockAVSDirectory.isOperatorRegistered(operator));

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0);
        assertEq(operatorData.commitment.delegateKey, "");
        assertEq(operatorData.commitment.chainIDBitMap, 0);
        assertEq(operatorData.pendingCommitment.delegateKey, "");
        assertEq(operatorData.pendingCommitment.chainIDBitMap, 0);
        assertEq(operatorData.startDeregisterOperatorBlock, 0);
        assertEq(operatorData.commitmentValidAfter, 0);
        assertTrue(operatorData.isRegistered);
    }

    function testRegisterOperator_AlreadyRegistered() public {
        _setupOperator();

        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _registerOperatorParams({ salt: bytes32(uint256(1)), expiry: uint256(block.timestamp + 1 days) });

        // 1st registration
        vm.prank(operator);
        avsManager.registerOperator(operatorSignature);
        assertTrue(mockAVSDirectory.isOperatorRegistered(operator));

        // 2nd registration
        vm.prank(operator);
        vm.expectRevert();
        avsManager.registerOperator(operatorSignature);
    }

    function testRegisterOperatorWithCommitment() public {
        _setupOperator();
        assertFalse(mockAVSDirectory.isOperatorRegistered(operator));

        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _registerOperatorParams({ salt: bytes32(uint256(1)), expiry: uint256(block.timestamp + 1 days) });

        OperatorCommitment memory initialCommitment =
            OperatorCommitment({ delegateKey: delegatePubKey, chainIDBitMap: 2 });

        vm.expectEmit(true, false, false, true);
        emit IUniFiAVSManager.OperatorRegisteredWithCommitment(operator, initialCommitment);

        vm.prank(operator);
        avsManager.registerOperatorWithCommitment(operatorSignature, initialCommitment);

        assertTrue(mockAVSDirectory.isOperatorRegistered(operator));

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey);
        assertEq(operatorData.commitment.chainIDBitMap, 2);
        assertEq(operatorData.pendingCommitment.delegateKey, "");
        assertEq(operatorData.pendingCommitment.chainIDBitMap, 0);
        assertEq(operatorData.startDeregisterOperatorBlock, 0);
        assertEq(operatorData.commitmentValidAfter, 0);
        assertTrue(operatorData.isRegistered);
    }

    function _setupValidators(bytes32[] memory blsPubKeyHashes) internal {
        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            mockEigenPodManager.setValidatorStatus(podOwner, blsPubKeyHashes[i], IEigenPod.VALIDATOR_STATUS.ACTIVE);
        }
    }

    function testRegisterValidators() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](2);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));
        blsPubKeyHashes[1] = keccak256(abi.encodePacked("validator2"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 2);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey);

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertEq(validatorData.eigenPod, address(mockEigenPodManager.getPod(podOwner)));
            assertEq(validatorData.operator, operator);
            assertTrue(validatorData.backedByEigenPodStake);
        }
    }

    function testRegisterValidators_OperatorNotRegistered() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.OperatorNotRegistered.selector);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);
    }

    function testRegisterValidators_DelegateKeyNotSet() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        // Clear the delegate key
        _setOperatorCommitment(operator, "", 0);

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.DelegateKeyNotSet.selector);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);
    }

    function testRegisterValidators_ValidatorNotActive() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();

        // Set validator status to inactive
        mockEigenPodManager.setValidatorStatus(podOwner, blsPubKeyHashes[0], IEigenPod.VALIDATOR_STATUS.INACTIVE);

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.ValidatorNotActive.selector);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);
    }

    function testRegisterValidators_ValidatorAlreadyRegistered() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        // Register the validator once
        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        // Try to register again
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.ValidatorAlreadyRegistered.selector);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);
    }

    function testDeregisterValidators() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](2);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));
        blsPubKeyHashes[1] = keccak256(abi.encodePacked("validator2"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 2);

        uint256 initialBlockNumber = block.number;
        vm.prank(operator);
        avsManager.deregisterValidators(blsPubKeyHashes);

        operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0, "all validators should be deregistered");

        vm.roll(initialBlockNumber + avsManager.getRegistrationDelay() + 1);
        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertTrue(validatorData.registered, "Validator should be registered");
        }

        // Advance block number to just before the deregistration delay
        vm.roll(initialBlockNumber + avsManager.getDeregistrationDelay() - 1);

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertTrue(validatorData.registered, "Validator should be registered before deregistrationDelay blocks");
        }

        // Advance block number to the deregistration delay
        vm.roll(initialBlockNumber + avsManager.getDeregistrationDelay());

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertFalse(validatorData.registered, "Validator should not be registered at deregistrationDelay blocks");
        }

        // Advance block number past the deregistration delay
        vm.roll(initialBlockNumber + avsManager.getDeregistrationDelay() + 1);

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertFalse(validatorData.registered, "Validator should not be registered after deregistrationDelay blocks");
        }
    }

    function testDeregisterValidators_ValidatorNoneExistent() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.NotValidatorOperator.selector);
        avsManager.deregisterValidators(blsPubKeyHashes);
    }

    function testDeregisterValidators_NotValidatorOperator() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        // Setup and register the first operator
        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        // Setup and register the second operator
        address secondOperator = address(0x456);
        uint256 secondOperatorPrivateKey = 789;
        vm.prank(secondOperator);
        mockDelegationManager.setOperator(secondOperator, true);

        ISignatureUtils.SignatureWithSaltAndExpiry memory secondOperatorSignature =
            _registerOperatorParams({ salt: bytes32(uint256(2)), expiry: uint256(block.timestamp + 1 days) });

        vm.prank(secondOperator);
        avsManager.registerOperator(secondOperatorSignature);

        // Attempt to deregister validators with the second operator
        vm.prank(secondOperator);
        vm.expectRevert(IUniFiAVSManager.NotValidatorOperator.selector);
        avsManager.deregisterValidators(blsPubKeyHashes);

        // Verify that the validators are still registered to the first operator
        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 1);
    }

    function testStartDeregisterOperator() public {
        _setupOperator();
        _registerOperator();

        vm.expectEmit(true, false, false, false);
        emit IUniFiAVSManager.OperatorDeregisterStarted(operator);

        vm.prank(operator);
        avsManager.startDeregisterOperator();

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.startDeregisterOperatorBlock, uint64(block.number));
    }

    function testStartDeregisterOperator_NotRegistered() public {
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.OperatorNotRegistered.selector);
        avsManager.startDeregisterOperator();
    }

    function testStartDeregisterOperator_HasValidators() public {
        _setupOperator();
        _registerOperator();

        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.OperatorHasValidators.selector);
        avsManager.startDeregisterOperator();
    }

    function testStartDeregisterOperator_AlreadyStarted() public {
        _setupOperator();
        _registerOperator();
        vm.roll(1); // advance so not at block 0

        vm.prank(operator);
        avsManager.startDeregisterOperator();

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.DeregistrationAlreadyStarted.selector);
        avsManager.startDeregisterOperator();
    }

    function testFinishDeregisterOperator() public {
        _setupOperator();
        _registerOperator();
        vm.roll(1); // advance so not at block 0

        vm.prank(operator);
        avsManager.startDeregisterOperator();

        vm.roll(block.number + avsManager.getDeregistrationDelay());

        vm.expectEmit(true, false, false, false);
        emit IUniFiAVSManager.OperatorDeregistered(operator);

        vm.prank(operator);
        avsManager.finishDeregisterOperator();

        assertFalse(mockAVSDirectory.isOperatorRegistered(operator), "Operator should be deregistered");
    }

    function testFinishDeregisterOperator_NotStarted() public {
        _setupOperator();
        _registerOperator();
        vm.roll(1); // advance so not at block 0

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.DeregistrationNotStarted.selector);
        avsManager.finishDeregisterOperator();
    }

    function testFinishDeregisterOperator_DelayNotElapsed() public {
        _setupOperator();
        _registerOperator();
        vm.roll(1); // advance so not at block 0

        vm.prank(operator);
        avsManager.startDeregisterOperator();

        vm.roll(block.number + avsManager.getDeregistrationDelay() - 1);

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.DeregistrationDelayNotElapsed.selector);
        avsManager.finishDeregisterOperator();
    }

    function testFinishDeregisterOperator_NotRegistered() public {
        vm.prank(operator);
        vm.roll(1); // advance so not at block 0
        vm.expectRevert(IUniFiAVSManager.OperatorNotRegistered.selector);
        avsManager.finishDeregisterOperator();
    }

    function testSetDeregistrationDelay() public {
        uint64 newDelay = 100;
        uint64 oldDelay = avsManager.getDeregistrationDelay();

        vm.expectEmit(true, true, false, true);
        emit IUniFiAVSManager.DeregistrationDelaySet(oldDelay, newDelay);

        vm.prank(DAO);
        avsManager.setDeregistrationDelay(newDelay);

        assertEq(avsManager.getDeregistrationDelay(), newDelay, "Deregistration delay should be updated");
    }

    function testGetValidator_backedByEigenPodStakeFalse() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        // Change delegation to a different address
        address randomAddress = makeAddr("random");
        mockDelegationManager.setDelegation(podOwner, randomAddress);

        ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[0]);

        assertEq(validatorData.operator, operator);
        assertFalse(
            validatorData.backedByEigenPodStake,
            "backedByEigenPodStake should be false when delegated to a different address"
        );
    }

    function testSetOperatorCommitment() public {
        _setupOperator();
        _registerOperator();

        bytes memory newDelegateKey = abi.encodePacked(uint256(2));
        uint256 newChainIDBitMap = 3; // 0b11

        vm.prank(operator);
        avsManager.setOperatorCommitment(
            OperatorCommitment({ delegateKey: newDelegateKey, chainIDBitMap: newChainIDBitMap })
        );

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey, "Delegate key should not change immediately");
        assertEq(operatorData.commitment.chainIDBitMap, 0, "Chain ID bitmap should not change immediately");
        assertEq(operatorData.pendingCommitment.delegateKey, newDelegateKey, "Pending delegate key should be set");
        assertEq(
            operatorData.pendingCommitment.chainIDBitMap, newChainIDBitMap, "Pending chain ID bitmap should be set"
        );
        assertEq(
            operatorData.commitmentValidAfter,
            block.number + avsManager.getDeregistrationDelay(),
            "Commitment valid after should be set correctly"
        );
    }

    function testUpdateOperatorCommitment() public {
        _setupOperator();
        _registerOperator();

        bytes memory newDelegateKey = abi.encodePacked(uint256(2));
        uint256 newChainIDBitMap = 3; // 0b11

        vm.prank(operator);
        avsManager.setOperatorCommitment(
            OperatorCommitment({ delegateKey: newDelegateKey, chainIDBitMap: newChainIDBitMap })
        );

        // advance to the update block
        vm.roll(block.number + avsManager.getDeregistrationDelay());

        vm.expectEmit(true, false, false, true);
        emit IUniFiAVSManager.OperatorCommitmentSet(
            operator,
            OperatorCommitment({ delegateKey: delegatePubKey, chainIDBitMap: 0 }),
            OperatorCommitment({ delegateKey: newDelegateKey, chainIDBitMap: newChainIDBitMap })
        );

        vm.prank(operator);
        avsManager.updateOperatorCommitment();

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.commitment.delegateKey, newDelegateKey, "Delegate key should be updated");
        assertEq(operatorData.commitment.chainIDBitMap, newChainIDBitMap, "Chain ID bitmap should be updated");
        assertEq(operatorData.pendingCommitment.delegateKey, "", "Pending delegate key should be cleared");
        assertEq(operatorData.pendingCommitment.chainIDBitMap, 0, "Pending chain ID bitmap should be cleared");
        assertEq(operatorData.commitmentValidAfter, 0, "Commitment valid after should be reset");
    }

    function testUpdateOperatorCommitment_TooEarly() public {
        _setupOperator();
        _registerOperator();

        bytes memory newDelegateKey = abi.encodePacked(uint256(2));
        uint256 newChainIDBitMap = 3; // 0b11

        vm.prank(operator);
        avsManager.setOperatorCommitment(
            OperatorCommitment({ delegateKey: newDelegateKey, chainIDBitMap: newChainIDBitMap })
        );

        vm.roll(block.number + avsManager.getDeregistrationDelay() - 1);

        vm.expectRevert(IUniFiAVSManager.CommitmentChangeNotReady.selector);
        vm.prank(operator);
        avsManager.updateOperatorCommitment();
    }

    function testSetOperatorCommitment_NotRegistered() public {
        bytes memory newDelegateKey = abi.encodePacked(uint256(2));
        uint256 newChainIDBitMap = 3; // 0b11

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.OperatorNotRegistered.selector);
        avsManager.setOperatorCommitment(
            OperatorCommitment({ delegateKey: newDelegateKey, chainIDBitMap: newChainIDBitMap })
        );
    }

    function testSetAndGetChainID() public {
        vm.startPrank(DAO);

        uint256 chainID1 = 1; // Ethereum Mainnet
        uint256 chainID2 = 10; // Optimism

        avsManager.setChainID(1, chainID1);
        avsManager.setChainID(2, chainID2);

        assertEq(avsManager.getChainID(1), chainID1, "ChainID at index 1 should match");
        assertEq(avsManager.getChainID(2), chainID2, "ChainID at index 2 should match");

        vm.stopPrank();
    }

    function testSetChainIDOutOfBounds() public {
        vm.startPrank(DAO);

        vm.expectRevert(IUniFiAVSManager.IndexOutOfBounds.selector);
        avsManager.setChainID(0, 1);

        vm.stopPrank();
    }

    function testSetChainIDUnauthorized() public {
        address unauthorizedUser = address(0x1234);
        vm.prank(unauthorizedUser);
        vm.expectRevert(); // todo get correct Unauthorized.selector
        avsManager.setChainID(0, 1);
    }

    function testGetChainIDOutOfBounds() public {
        uint256 chainID = avsManager.getChainID(0);

        assertEq(chainID, 0, "Should return zero");
    }

    function testSetDeregistrationDelayUnauthorized() public {
        address unauthorizedUser = address(0x1234);
        vm.prank(unauthorizedUser);
        vm.expectRevert(); // todo get correct Unauthorized.selector
        avsManager.setDeregistrationDelay(100);
    }

    function testBitmapToChainIDs() public {
        vm.startPrank(DAO);

        avsManager.setChainID(1, 1); // Ethereum Mainnet
        avsManager.setChainID(2, 10); // Optimism
        avsManager.setChainID(3, 137); // Polygon
        avsManager.setChainID(255, 1111); // New chain ID at index 255

        uint256 bitmap = 0x800000000000000000000000000000000000000000000000000000000000000e; // 0b1000...1110 (255th and 1st, 2nd, 3rd bits set)

        uint256[] memory chainIDs = avsManager.bitmapToChainIDs(bitmap);

        assertEq(chainIDs.length, 4, "Should return 4 chainIDs");
        assertEq(chainIDs[0], 1, "First chainID should match");
        assertEq(chainIDs[1], 10, "Second chainID should match");
        assertEq(chainIDs[2], 137, "Third chainID should match");
        assertEq(chainIDs[3], 1111, "Fourth chainID should match");

        vm.stopPrank();
    }

    function testBitmapToChainIDsWithGaps() public {
        vm.startPrank(DAO);

        avsManager.setChainID(1, 1); // Ethereum Mainnet
        avsManager.setChainID(3, 137); // Polygon

        uint256 bitmap = 0xA; // 0b1010

        uint256[] memory chainIDs = avsManager.bitmapToChainIDs(bitmap);

        assertEq(chainIDs.length, 2, "Should return 2 chainIDs");
        assertEq(chainIDs[0], 1, "First chainID should match");
        assertEq(chainIDs[1], 137, "Second chainID should match");

        vm.stopPrank();
    }

    function testGetBitmapIndex() public {
        vm.startPrank(DAO);

        uint32 chainID1 = 1; // Ethereum Mainnet
        uint32 chainID2 = 10; // Optimism

        avsManager.setChainID(1, chainID1);
        avsManager.setChainID(2, chainID2);

        assertEq(avsManager.getBitmapIndex(chainID1), 1, "Bitmap index for chainID1 should be 1");
        assertEq(avsManager.getBitmapIndex(chainID2), 2, "Bitmap index for chainID2 should be 2");

        vm.stopPrank();
    }

    function testGetBitmapIndexNonExistent() public {
        uint32 nonExistentChainID = 999;

        assertEq(
            avsManager.getBitmapIndex(nonExistentChainID),
            0,
            "Bitmap index for non-existent chainID should be type(uint8).max"
        );
    }

    function testIsValidatorInChainId() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        // Set chain IDs
        vm.startPrank(DAO);
        avsManager.setChainID(1, 1); // Ethereum Mainnet
        avsManager.setChainID(2, 10); // Optimism
        avsManager.setChainID(3, 137); // Polygon
        vm.stopPrank();

        // Set a chainIDBitMap for the operator
        uint256 chainIDBitMap = 0x5; // 0b101, active for chain IDs at index 1 and 3
        _setOperatorCommitment(operator, delegatePubKey, chainIDBitMap);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        assertTrue(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 1), "Validator should be in Ethereum Mainnet");
        assertFalse(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 10), "Validator should not be in Optimism");
        assertTrue(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 137), "Validator should be in Polygon");
        assertFalse(
            avsManager.isValidatorInChainId(blsPubKeyHashes[0], 42161), "Validator should not be in Arbitrum One"
        );
    }

    function testIsValidatorInChainId_ValidatorNotFound() public {
        bytes32 nonExistentValidator = keccak256(abi.encodePacked("nonExistentValidator"));

        assertFalse(
            avsManager.isValidatorInChainId(nonExistentValidator, 1),
            "Non-existent validator should not be in any chain"
        );
    }

    function testGetOperatorRestakedStrategies() public {
        _setupOperator();
        _registerOperator();

        // Set shares for the operator
        mockDelegationManager.setShares(operator, IStrategy(BEACON_CHAIN_STRATEGY), 100);

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 1, "Should return one restaked strategy");
        assertEq(restakedStrategies[0], BEACON_CHAIN_STRATEGY, "Should return BEACON_CHAIN_STRATEGY");
    }

    function testGetRestakeableStrategies() public {
        address[] memory restakeableStrategies = avsManager.getRestakeableStrategies();

        assertEq(restakeableStrategies.length, 1, "Should return one restakeable strategy");
        assertEq(restakeableStrategies[0], BEACON_CHAIN_STRATEGY, "Should return BEACON_CHAIN_STRATEGY");
    }

    function testIsValidatorInChainId_AfterCommitmentChange() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        // Set chain IDs
        vm.startPrank(DAO);
        avsManager.setChainID(1, 1); // Ethereum Mainnet
        avsManager.setChainID(2, 10); // Optimism
        avsManager.setChainID(3, 137); // Polygon
        vm.stopPrank();

        // Initial chainIDBitMap
        uint256 initialChainIDBitMap = 0x5; // 0b101, active for chain IDs at index 1 and 3
        _setOperatorCommitment(operator, delegatePubKey, initialChainIDBitMap);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        // Change the commitment
        uint256 newChainIDBitMap = 0x6; // 0b110, active for chain IDs at index 2 and 3
        vm.prank(operator);
        avsManager.setOperatorCommitment(
            OperatorCommitment({ delegateKey: delegatePubKey, chainIDBitMap: newChainIDBitMap })
        );

        // Before the commitment change takes effect
        assertTrue(
            avsManager.isValidatorInChainId(blsPubKeyHashes[0], 1), "Validator should still be in Ethereum Mainnet"
        );
        assertFalse(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 10), "Validator should not yet be in Optimism");

        // Advance to make the new commitment active
        vm.roll(block.number + avsManager.getDeregistrationDelay());

        vm.prank(operator);
        avsManager.updateOperatorCommitment();

        // After the commitment change takes effect
        assertFalse(
            avsManager.isValidatorInChainId(blsPubKeyHashes[0], 1), "Validator should no longer be in Ethereum Mainnet"
        );
        assertTrue(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 10), "Validator should now be in Optimism");
        assertTrue(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 137), "Validator should still be in Polygon");
    }

    function test_deregisterAlreadyDeregisteredValidator() public {
        // Register an operator
        _setupOperator();
        _registerOperator();

        // Register a validator
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = bytes32(uint256(1));
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        // Deregister the validator
        vm.prank(operator);
        avsManager.deregisterValidators(blsPubKeyHashes);

        // Attempt to deregister the same validator again
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IUniFiAVSManager.ValidatorAlreadyDeregistered.selector));
        avsManager.deregisterValidators(blsPubKeyHashes);
    }

    function test_deregisterMixedValidators() public {
        // Register an operator
        _setupOperator();
        _registerOperator();

        // Register two validators
        bytes32[] memory blsPubKeyHashes = new bytes32[](2);
        blsPubKeyHashes[0] = bytes32(uint256(1));
        blsPubKeyHashes[1] = bytes32(uint256(2));
        _setupValidators(blsPubKeyHashes);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);
        vm.roll(block.number + avsManager.getRegistrationDelay() + 1);

        // Deregister the first validator
        bytes32[] memory deregisterFirst = new bytes32[](1);
        deregisterFirst[0] = blsPubKeyHashes[0];
        vm.prank(operator);
        avsManager.deregisterValidators(deregisterFirst);

        // Attempt to deregister both validators (one already deregistered, one still registered)
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IUniFiAVSManager.ValidatorAlreadyDeregistered.selector));
        avsManager.deregisterValidators(blsPubKeyHashes);

        // Verify that the second validator is still registered
        ValidatorDataExtended memory validator = avsManager.getValidator(blsPubKeyHashes[1]);
        assertTrue(validator.registered, "Second validator should still be registered");

        // Successfully deregister the second validator
        bytes32[] memory deregisterSecond = new bytes32[](1);
        deregisterSecond[0] = blsPubKeyHashes[1];
        vm.prank(operator);
        avsManager.deregisterValidators(deregisterSecond);

        // Roll forward to simulate time passing
        uint256 deregistrationDelay = avsManager.getDeregistrationDelay();
        vm.roll(block.number + deregistrationDelay + 1);

        validator = avsManager.getValidator(blsPubKeyHashes[0]);
        assertFalse(validator.registered, "First validator should be deregistered");
    }

    function testUpdateAVSMetadataURI() public {
        string memory newMetadataURI = "https://example.com/new-metadata";

        vm.expectEmit(true, true, false, true);
        emit IAVSDirectory.AVSMetadataURIUpdated(address(avsManager), newMetadataURI);

        vm.prank(DAO);
        avsManager.updateAVSMetadataURI(newMetadataURI);
    }

    function testSetAllowlistRestakingStrategy() public {
        address newStrategy = address(0x123);

        // Initially, only BEACON_CHAIN_STRATEGY should be allowlisted
        address[] memory initialStrategies = avsManager.getRestakeableStrategies();
        assertEq(initialStrategies.length, 1);
        assertEq(initialStrategies[0], BEACON_CHAIN_STRATEGY);

        // Add a new strategy
        vm.prank(DAO);
        vm.expectEmit(true, true, false, true);
        emit IUniFiAVSManager.RestakingStrategyAllowlistUpdated(newStrategy, true);
        avsManager.setAllowlistRestakingStrategy(newStrategy, true);

        // Check that the new strategy is added
        address[] memory updatedStrategies = avsManager.getRestakeableStrategies();
        assertEq(updatedStrategies.length, 2);
        assertTrue(updatedStrategies[0] == BEACON_CHAIN_STRATEGY || updatedStrategies[1] == BEACON_CHAIN_STRATEGY);
        assertTrue(updatedStrategies[0] == newStrategy || updatedStrategies[1] == newStrategy);

        // Remove the new strategy
        vm.prank(DAO);
        vm.expectEmit(true, true, false, true);
        emit IUniFiAVSManager.RestakingStrategyAllowlistUpdated(newStrategy, false);
        avsManager.setAllowlistRestakingStrategy(newStrategy, false);

        // Check that the strategy is removed
        address[] memory finalStrategies = avsManager.getRestakeableStrategies();
        assertEq(finalStrategies.length, 1);
        assertEq(finalStrategies[0], BEACON_CHAIN_STRATEGY);

        // Try to remove newStrategy (should fail)
        vm.prank(DAO);
        vm.expectRevert(IUniFiAVSManager.RestakingStrategyAllowlistUpdateFailed.selector);
        avsManager.setAllowlistRestakingStrategy(newStrategy, false);
    }

    function testSetAllowlistRestakingStrategy_Unauthorized() public {
        address newStrategy = address(0x123);

        vm.prank(operator);
        vm.expectRevert();
        avsManager.setAllowlistRestakingStrategy(newStrategy, true);
    }

    function testGetOperatorRestakedStrategies_MultipleStrategies() public {
        _setupOperator();
        _registerOperator();

        address newStrategy1 = address(0x123);
        address newStrategy2 = address(0x456);

        // Add new strategies to the allowlist
        vm.startPrank(DAO);
        avsManager.setAllowlistRestakingStrategy(newStrategy1, true);
        avsManager.setAllowlistRestakingStrategy(newStrategy2, true);
        vm.stopPrank();

        // Set shares for the operator
        mockDelegationManager.setShares(operator, IStrategy(BEACON_CHAIN_STRATEGY), 100);
        mockDelegationManager.setShares(operator, IStrategy(newStrategy1), 200);
        // Note: We don't set shares for newStrategy2

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 2, "Should return two restaked strategies");
        assertTrue(
            restakedStrategies[0] == BEACON_CHAIN_STRATEGY || restakedStrategies[1] == BEACON_CHAIN_STRATEGY,
            "Should include BEACON_CHAIN_STRATEGY"
        );
        assertTrue(
            restakedStrategies[0] == newStrategy1 || restakedStrategies[1] == newStrategy1,
            "Should include newStrategy1"
        );
    }

    function testGetOperatorRestakedStrategies_NoShares() public {
        _setupOperator();
        _registerOperator();

        address newStrategy = address(0x123);

        // Add new strategy to the allowlist
        vm.prank(DAO);
        avsManager.setAllowlistRestakingStrategy(newStrategy, true);

        // Don't set any shares for the operator

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 0, "Should return no restaked strategies");
    }

    function testGetOperatorRestakedStrategies_NotRegistered() public {
        _setupOperator();
        // Don't register the operator

        address newStrategy = address(0x123);

        // Add new strategy to the allowlist
        vm.prank(DAO);
        avsManager.setAllowlistRestakingStrategy(newStrategy, true);

        // Set shares for the operator
        mockDelegationManager.setShares(operator, IStrategy(BEACON_CHAIN_STRATEGY), 100);
        mockDelegationManager.setShares(operator, IStrategy(newStrategy), 200);

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 0, "Should return no restaked strategies for unregistered operator");
    }

    function testRegisterValidatorsOptimistically() public {
        _setupOperator();
        _registerOperator();

        uint256 validatorPrivateKey1 = 123;
        uint256 validatorPrivateKey2 = 456;
        uint64 validatorIndex1 = 1;
        uint64 validatorIndex2 = 2;
        uint64 salt1 = 1;
        uint64 salt2 = 2;
        uint256 expiry = block.timestamp + 1 days;

        (BN254.G1Point memory signature1, bytes32 pubkeyHash1) =
            _getValidatorSignature(validatorPrivateKey1, validatorIndex1, operator, salt1, expiry);

        (BN254.G1Point memory signature2, bytes32 pubkeyHash2) =
            _getValidatorSignature(validatorPrivateKey2, validatorIndex2, operator, salt2, expiry);

        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](2);
        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash1,
            registrationSignature: signature1,
            index: validatorIndex1,
            expiry: expiry,
            salt: salt1
        });

        paramsArray[1] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash2,
            registrationSignature: signature2,
            index: validatorIndex2,
            expiry: expiry,
            salt: salt2
        });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 2, "Validator count should be 2");
        vm.roll(block.number + avsManager.getRegistrationDelay() + 1);

        ValidatorDataExtended memory validator1 = avsManager.getValidator(pubkeyHash1);
        ValidatorDataExtended memory validator2 = avsManager.getValidator(pubkeyHash2);

        assertTrue(validator1.registered, "Validator 1 should be registered");
        assertTrue(validator2.registered, "Validator 2 should be registered");
        assertEq(validator1.operator, operator, "Validator 1 should be assigned to the correct operator");
        assertEq(validator2.operator, operator, "Validator 2 should be assigned to the correct operator");
    }

    function testslashValidatorsWithInvalidSignature() public {
        _setupOperator();
        _registerOperator();

        uint256 validatorPrivateKey = 123;
        uint64 validatorIndex = 1;
        uint64 salt = 1;
        uint256 expiry = block.timestamp + 1 days;

        (BN254.G1Point memory signature, bytes32 pubkeyHash) =
            _getValidatorSignature(validatorPrivateKey, validatorIndex, operator, salt, expiry);

        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](1);
        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash,
            registrationSignature: signature,
            index: validatorIndex,
            expiry: expiry,
            salt: salt
        });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        ValidatorRegistrationSlashingParams[] memory slashingParams = new ValidatorRegistrationSlashingParams[](1);
        slashingParams[0] = ValidatorRegistrationSlashingParams({
            pubkeyG1: _generateBlsPubkeyParams(validatorPrivateKey).pubkeyG1,
            pubkeyG2: _generateBlsPubkeyParams(validatorPrivateKey).pubkeyG2,
            registrationSignature: signature,
            index: validatorIndex,
            expiry: expiry,
            salt: salt
        });

        avsManager.slashValidatorsWithInvalidSignature(slashingParams);
        vm.roll(block.number + avsManager.getRegistrationDelay() + 1);

        ValidatorDataExtended memory validator = avsManager.getValidator(pubkeyHash);
        assertTrue(validator.registered, "Validator should still be registered after verification");
    }

    function testslashValidatorsWithInvalidSignature_InvalidSignature() public {
        _setupOperator();
        _registerOperator();

        uint256 validatorPrivateKey = 123;
        uint64 validatorIndex = 1;
        uint64 salt = 1;
        uint256 expiry = block.timestamp + 1 days;

        (BN254.G1Point memory validSignature, bytes32 pubkeyHash) =
            _getValidatorSignature(validatorPrivateKey, validatorIndex, operator, salt, expiry);

        // Create an invalid signature by using a different private key
        (BN254.G1Point memory invalidSignature,) = _getValidatorSignature(
            456, // Different private key
            validatorIndex,
            operator,
            salt,
            expiry
        );

        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](1);
        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash,
            registrationSignature: invalidSignature,
            index: validatorIndex,
            expiry: expiry,
            salt: salt
        });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        ValidatorRegistrationSlashingParams[] memory slashingParams = new ValidatorRegistrationSlashingParams[](1);
        slashingParams[0] = ValidatorRegistrationSlashingParams({
            pubkeyG1: _generateBlsPubkeyParams(validatorPrivateKey).pubkeyG1,
            pubkeyG2: _generateBlsPubkeyParams(validatorPrivateKey).pubkeyG2,
            registrationSignature: invalidSignature,
            index: validatorIndex,
            expiry: expiry,
            salt: salt
        });

        vm.expectEmit(true, true, false, false);
        emit IUniFiAVSManager.ValidatorSlashed(operator, pubkeyHash);

        avsManager.slashValidatorsWithInvalidSignature(slashingParams);

        vm.roll(block.number + avsManager.getDeregistrationDelay() + 1);
        ValidatorDataExtended memory validator = avsManager.getValidator(pubkeyHash);
        assertFalse(validator.registered, "Validator should be deregistered after invalid signature verification");

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0, "Operator should have no validators after slashing");
    }

    function testVerifyValidatorOnBeaconChainValidProofAndValidator() public {
        _setupOperator();
        _registerOperator();
        vm.warp(block.timestamp + 50);
        // Register the validator optimistically
        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](1);
        bytes32 pubkeyHash = sha256(abi.encodePacked(BeaconProofs.validator(), bytes16(0)));

        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash,
            salt: 1,
            expiry: block.timestamp + 1 days,
            index: uint64(BeaconProofs.validatorIndex()),
            registrationSignature: _generateBlsPubkeyParams(123).pubkeyG1 // Use a dummy value for the signature
         });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        // Prepare the data for verification
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = pubkeyHash;

        BeaconChainHelperLib.InclusionProof[] memory proofs = new BeaconChainHelperLib.InclusionProof[](1);

        proofs[0] = BeaconProofs.eip4788ValidatorInclusionProof();
        proofs[0].timestamp = block.number + avsManager.getRegistrationDelay() + 1;
        // Mock the getRootFromTimestamp function to return the expected beacon block root
        vm.mockCall(
            address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02),
            hex"00000000",
            abi.encode(BeaconProofs.beaconBlockRoot())
        );

        // Verify the validator on the beacon chain
        avsManager.slashValidatorsWithInvalidIndex(proofs);
        vm.roll(block.number + avsManager.getRegistrationDelay() + 1);

        // Check that the validator is still registered
        ValidatorDataExtended memory validator = avsManager.getValidator(blsPubKeyHashes[0]);
        assertTrue(validator.registered, "Validator should still be registered after successful verification");
    }

    function testSlashValidatorsWithInvalidIndex() public {
        _setupOperator();
        _registerOperator();
        vm.warp(block.timestamp + 50);
        // Register the validator optimistically
        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](1);
        bytes32 pubkeyHash = sha256(abi.encodePacked(BeaconProofs.validator(), bytes16(0)));

        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash,
            salt: 1,
            expiry: block.timestamp + 1 days,
            index: 1, // Use a different index
            registrationSignature: _generateBlsPubkeyParams(123).pubkeyG1 // Use a dummy value for the signature
         });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        // Prepare the data for verification
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = pubkeyHash;

        BeaconChainHelperLib.InclusionProof[] memory proofs = new BeaconChainHelperLib.InclusionProof[](1);
        proofs[0] = BeaconProofs.eip4788ValidatorInclusionProof();
        proofs[0].timestamp = block.number + avsManager.getRegistrationDelay() + 1;
        // Mock the getRootFromTimestamp function to return the expected beacon block root
        vm.mockCall(
            address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02),
            hex"00000000",
            abi.encode(BeaconProofs.beaconBlockRoot())
        );

        // Verify the validator on the beacon chain
        avsManager.slashValidatorsWithInvalidIndex(proofs);

        // Check that the validator is still registered
        ValidatorDataExtended memory validator = avsManager.getValidator(blsPubKeyHashes[0]);
        assertFalse(validator.registered, "Validator should be deregistered after slashing");

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0, "Operator should have no validators after slashing");
    }

    function testSlashValidatorsWithInvalidPubkey() public {
        _setupOperator();
        _registerOperator();
        vm.warp(block.timestamp + 50);
        // Register the validator optimistically
        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](1);
        bytes32 pubkeyHash = sha256(abi.encodePacked(BeaconProofs.validator(), bytes16(0)));

        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: bytes32(uint256(1234)),
            salt: 1,
            expiry: block.timestamp + 1 days,
            index: uint64(BeaconProofs.validatorIndex()),
            registrationSignature: _generateBlsPubkeyParams(123).pubkeyG1 // Use a dummy value for the signature
         });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        // Prepare the data for verification
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = pubkeyHash;

        BeaconChainHelperLib.InclusionProof[] memory proofs = new BeaconChainHelperLib.InclusionProof[](1);
        proofs[0] = BeaconProofs.eip4788ValidatorInclusionProof();
        proofs[0].timestamp = block.number + avsManager.getRegistrationDelay() + 1;
        // Mock the getRootFromTimestamp function to return the expected beacon block root
        vm.mockCall(
            address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02),
            hex"00000000",
            abi.encode(BeaconProofs.beaconBlockRoot())
        );

        // Verify the validator on the beacon chain
        avsManager.slashValidatorsWithInvalidPubkey(proofs);

        // Check that the validator is still registered
        ValidatorDataExtended memory validator = avsManager.getValidator(bytes32(uint256(1234)));
        assertFalse(validator.registered, "Validator should be deregistered after slashing");

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0, "Operator should have no validators after slashing");
    }

    function testSlashValidatorsWithInvalidProof() public {
        _setupOperator();
        _registerOperator();
        vm.warp(block.timestamp + 50);
        // Register the validator optimistically
        ValidatorRegistrationParams[] memory paramsArray = new ValidatorRegistrationParams[](1);
        bytes32 pubkeyHash = sha256(abi.encodePacked(BeaconProofs.validator(), bytes16(0)));
        paramsArray[0] = ValidatorRegistrationParams({
            blsPubKeyHash: pubkeyHash,
            salt: 1,
            expiry: block.timestamp + 1 days,
            index: uint64(BeaconProofs.validatorIndex()),
            registrationSignature: _generateBlsPubkeyParams(123).pubkeyG1 // Use a dummy value for the signature
         });

        vm.prank(operator);
        avsManager.registerValidatorsOptimistically(paramsArray);

        // Prepare the data for verification
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = pubkeyHash;

        BeaconChainHelperLib.InclusionProof[] memory proofs = new BeaconChainHelperLib.InclusionProof[](1);
        proofs[0] = BeaconProofs.eip4788ValidatorInclusionProof();

        // Mock the getRootFromTimestamp function to return an incorrect beacon block root
        vm.mockCall(
            address(0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02),
            hex"00000000",
            abi.encode(bytes32(uint256(1))) // Incorrect beacon block root
        );

        // Expect the verification to fail
        vm.expectRevert(abi.encodeWithSelector(IUniFiAVSManager.InvalidValidatorProof.selector, pubkeyHash));
        avsManager.slashValidatorsWithInvalidPubkey(proofs);

        // Check that the validator is not slashed nor deregistered
        vm.roll(block.number + avsManager.getDeregistrationDelay() + 1);
        ValidatorDataExtended memory validator = avsManager.getValidator(blsPubKeyHashes[0]);
        assertTrue(validator.registered, "Validator should be still registered after failed slashing");

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 1, "Operator should have 1 validator after failed slashing");
    }
}
