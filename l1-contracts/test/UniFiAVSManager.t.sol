// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IUniFiAVSManager } from "../src/interfaces/IUniFiAVSManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { BN254 } from "eigenlayer-middleware/libraries/BN254.sol";
import { IBLSApkRegistry } from "eigenlayer-middleware/interfaces/IBLSApkRegistry.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { UnitTestHelper } from "../test/helpers/UnitTestHelper.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import { IRewardsCoordinator } from "eigenlayer/interfaces/IRewardsCoordinator.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract UniFiAVSManagerTest is UnitTestHelper {
    using BN254 for BN254.G1Point;
    using Strings for uint256;

    bytes internal delegatePubKey = abi.encodePacked(uint256(1337));

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

    // With ECDSA key, he sign the hash confirming that the operator wants to be registered to a certain restaking service
    function _getOperatorSignature(uint256 _operatorPrivateKey, address avs, bytes32 salt, uint256 expiry)
        internal
        view
        returns (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    {
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
        view
        returns (ISignatureUtils.SignatureWithSaltAndExpiry memory)
    {
        (, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) = _getOperatorSignature({
            _operatorPrivateKey: operatorPrivateKey,
            avs: address(avsManager),
            salt: salt,
            expiry: expiry
        });

        return operatorSignature;
    }

    function _registerOperator() public {
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            _registerOperatorParams({ salt: bytes32(uint256(1)), expiry: uint256(block.timestamp + 1 days) });

        vm.prank(operator);
        avsManager.registerOperator(operatorSignature);

        _setOperatorCommitment(operator, delegatePubKey, new uint256[](0));
    }

    function _setOperatorCommitment(address _operator, bytes memory _delegateKey, uint256[] memory _chainIds)
        internal
    {
        vm.prank(_operator);
        avsManager.setOperatorCommitment(
            IUniFiAVSManager.OperatorCommitment({ delegateKey: _delegateKey, chainIds: _chainIds })
        );

        vm.roll(block.number + avsManager.getDeregistrationDelay());
    }

    // BEGIN TESTS

    function testInitialize() public view {
        // todo add appropriate initialization checks here
        assertTrue(address(avsManager) != address(0));
    }

    function test_registerOperatorHelper() public {
        _setupOperator();
        assertFalse(mockAVSDirectory.isOperatorRegistered(operator));
        _registerOperator();
        assertTrue(mockAVSDirectory.isOperatorRegistered(operator));

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey);
        assertEq(operatorData.commitment.chainIds.length, 0);
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

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0);
        assertEq(operatorData.commitment.delegateKey, "");
        assertEq(operatorData.commitment.chainIds.length, 0);
        assertEq(operatorData.pendingCommitment.delegateKey, "");
        assertEq(operatorData.pendingCommitment.chainIds.length, 0);
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

        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = 1;

        IUniFiAVSManager.OperatorCommitment memory initialCommitment =
            IUniFiAVSManager.OperatorCommitment({ delegateKey: delegatePubKey, chainIds: chainIds });

        vm.expectEmit(true, false, false, true);
        emit IUniFiAVSManager.OperatorRegisteredWithCommitment(operator, initialCommitment);

        vm.prank(operator);
        avsManager.registerOperatorWithCommitment(operatorSignature, initialCommitment);

        assertTrue(mockAVSDirectory.isOperatorRegistered(operator));

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey);
        assertEq(operatorData.commitment.chainIds.length, 1);
        assertEq(operatorData.commitment.chainIds[0], 1);
        assertEq(operatorData.pendingCommitment.delegateKey, "");
        assertEq(operatorData.pendingCommitment.chainIds.length, 0);
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

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 2);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey);

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            IUniFiAVSManager.ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertEq(validatorData.eigenPod, address(mockEigenPodManager.getPod(podOwner)));
            assertEq(validatorData.operator, operator);
            assertTrue(validatorData.backedByStake);
        }

        IUniFiAVSManager.ValidatorDataExtended[] memory validators = avsManager.getValidators(blsPubKeyHashes);
        assertEq(validators.length, 2, "should return 2 validators");

        IUniFiAVSManager.ValidatorDataExtended memory validator = avsManager.getValidatorByIndex(uint64(uint256(blsPubKeyHashes[0])));
        assertEq(validator.operator, operator, "should return the correct operator");
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
        _setOperatorCommitment(operator, "", new uint256[](0));

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

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 2);

        vm.prank(operator);
        avsManager.deregisterValidators(blsPubKeyHashes);

        operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 0, "all validators should be deregistered");

        for (uint256 i = 0; i < blsPubKeyHashes.length; i++) {
            IUniFiAVSManager.ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[i]);
            assertFalse(validatorData.registered, "Validator should not be registered");
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
        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.validatorCount, 1);
    }

    function testStartDeregisterOperator() public {
        _setupOperator();
        _registerOperator();

        vm.expectEmit(true, false, false, false);
        emit IUniFiAVSManager.OperatorDeregisterStarted(operator);

        vm.prank(operator);
        avsManager.startDeregisterOperator();

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
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

    function testGetValidator_BackedByStakeFalse() public {
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

        IUniFiAVSManager.ValidatorDataExtended memory validatorData = avsManager.getValidator(blsPubKeyHashes[0]);

        assertEq(validatorData.operator, operator);
        assertFalse(validatorData.backedByStake, "backedByStake should be false when delegated to a different address");
    }

    function testSetOperatorCommitment() public {
        _setupOperator();
        _registerOperator();

        bytes memory newDelegateKey = abi.encodePacked(uint256(2));
        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 1;
        newChainIds[1] = 1337;

        vm.prank(operator);
        avsManager.setOperatorCommitment(
            IUniFiAVSManager.OperatorCommitment({ delegateKey: newDelegateKey, chainIds: newChainIds })
        );

        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.commitment.delegateKey, delegatePubKey, "Delegate key should not change immediately");
        assertEq(operatorData.commitment.chainIds.length, 0, "Chain ID bitmap should not change immediately");
        assertEq(operatorData.pendingCommitment.delegateKey, newDelegateKey, "Pending delegate key should be set");
        assertEq(
            operatorData.pendingCommitment.chainIds.length, newChainIds.length, "Pending chain ID bitmap should be set"
        );
        for (uint256 i = 0; i < newChainIds.length; i++) {
            assertEq(operatorData.pendingCommitment.chainIds[i], newChainIds[i], "Pending chain ID should be set");
        }
        assertEq(
            operatorData.commitmentValidAfter,
            block.number + avsManager.getDeregistrationDelay(),
            "Commitment valid after should be set correctly"
        );
    }

    function testSetOperatorCommitment_NotRegistered() public {
        bytes memory newDelegateKey = abi.encodePacked(uint256(2));
        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 1;
        newChainIds[1] = 1337;

        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.OperatorNotRegistered.selector);
        avsManager.setOperatorCommitment(
            IUniFiAVSManager.OperatorCommitment({ delegateKey: newDelegateKey, chainIds: newChainIds })
        );
    }

    function testSetDeregistrationDelayUnauthorized() public {
        address unauthorizedUser = address(0x1234);
        vm.prank(unauthorizedUser);
        vm.expectRevert(); // todo get correct Unauthorized.selector
        avsManager.setDeregistrationDelay(100);
    }

    function testIsValidatorInChainId() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        uint256[] memory chainIds = new uint256[](2);
        chainIds[0] = 1;
        chainIds[1] = 137;

        _setOperatorCommitment(operator, delegatePubKey, chainIds);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        assertTrue(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 1), "Validator should be in Ethereum Mainnet");
        assertFalse(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 10), "Validator should not be in Optimism");
        assertTrue(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 137), "Validator should be in Polygon");
        assertFalse(
            avsManager.isValidatorInChainId(blsPubKeyHashes[0], 42161), "Validator should not be in Arbitrum One"
        );
    }

    function testIsValidatorInChainId_ValidatorNotFound() public view {
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
        mockDelegationManager.setShares(operator, IStrategy(avsManager.BEACON_CHAIN_STRATEGY()), 100);

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 1, "Should return one restaked strategy");
        assertEq(restakedStrategies[0], avsManager.BEACON_CHAIN_STRATEGY(), "Should return BEACON_CHAIN_STRATEGY");
    }

    function testGetRestakeableStrategies() public view {
        address[] memory restakeableStrategies = avsManager.getRestakeableStrategies();

        assertEq(restakeableStrategies.length, 1, "Should return one restakeable strategy");
        assertEq(restakeableStrategies[0], avsManager.BEACON_CHAIN_STRATEGY(), "Should return BEACON_CHAIN_STRATEGY");
    }

    function testIsValidatorInChainId_AfterCommitmentChange() public {
        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("validator1"));

        _setupOperator();
        _registerOperator();
        _setupValidators(blsPubKeyHashes);

        uint256[] memory initialChainIds = new uint256[](2);
        initialChainIds[0] = 1;
        initialChainIds[1] = 137;
        _setOperatorCommitment(operator, delegatePubKey, initialChainIds);

        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

        // Change the commitment
        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 10;
        newChainIds[1] = 137;
        vm.prank(operator);
        avsManager.setOperatorCommitment(
            IUniFiAVSManager.OperatorCommitment({ delegateKey: delegatePubKey, chainIds: newChainIds })
        );

        // Before the commitment change takes effect
        assertTrue(
            avsManager.isValidatorInChainId(blsPubKeyHashes[0], 1), "Validator should still be in Ethereum Mainnet"
        );
        assertFalse(avsManager.isValidatorInChainId(blsPubKeyHashes[0], 10), "Validator should not yet be in Optimism");

        // Advance to make the new commitment active
        vm.roll(block.number + avsManager.getDeregistrationDelay());

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
        IUniFiAVSManager.ValidatorDataExtended memory validator = avsManager.getValidator(blsPubKeyHashes[1]);
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
        assertEq(initialStrategies[0], avsManager.BEACON_CHAIN_STRATEGY());

        // Add a new strategy
        vm.prank(DAO);
        vm.expectEmit(true, true, false, true);
        emit IUniFiAVSManager.RestakingStrategyAllowlistUpdated(newStrategy, true);
        avsManager.setAllowlistRestakingStrategy(newStrategy, true);

        // Check that the new strategy is added
        address[] memory updatedStrategies = avsManager.getRestakeableStrategies();
        assertEq(updatedStrategies.length, 2);
        assertTrue(
            updatedStrategies[0] == avsManager.BEACON_CHAIN_STRATEGY()
                || updatedStrategies[1] == avsManager.BEACON_CHAIN_STRATEGY()
        );
        assertTrue(updatedStrategies[0] == newStrategy || updatedStrategies[1] == newStrategy);

        // Remove the new strategy
        vm.prank(DAO);
        vm.expectEmit(true, true, false, true);
        emit IUniFiAVSManager.RestakingStrategyAllowlistUpdated(newStrategy, false);
        avsManager.setAllowlistRestakingStrategy(newStrategy, false);

        // Check that the strategy is removed
        address[] memory finalStrategies = avsManager.getRestakeableStrategies();
        assertEq(finalStrategies.length, 1);
        assertEq(finalStrategies[0], avsManager.BEACON_CHAIN_STRATEGY());

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
        mockDelegationManager.setShares(operator, IStrategy(avsManager.BEACON_CHAIN_STRATEGY()), 100);
        mockDelegationManager.setShares(operator, IStrategy(newStrategy1), 200);
        // Note: We don't set shares for newStrategy2

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 2, "Should return two restaked strategies");
        assertTrue(
            restakedStrategies[0] == avsManager.BEACON_CHAIN_STRATEGY()
                || restakedStrategies[1] == avsManager.BEACON_CHAIN_STRATEGY(),
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
        mockDelegationManager.setShares(operator, IStrategy(avsManager.BEACON_CHAIN_STRATEGY()), 100);
        mockDelegationManager.setShares(operator, IStrategy(newStrategy), 200);

        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        assertEq(restakedStrategies.length, 0, "Should return no restaked strategies for unregistered operator");
    }

    function testSubmitOperatorRewards() public {
        // Create mock rewards submission data
        IRewardsCoordinator.OperatorReward[] memory operatorRewards = new IRewardsCoordinator.OperatorReward[](2);
        operatorRewards[0] = IRewardsCoordinator.OperatorReward({ operator: address(0x1), amount: 100 });
        operatorRewards[1] = IRewardsCoordinator.OperatorReward({ operator: address(operator), amount: 200 });

        IRewardsCoordinator.StrategyAndMultiplier[] memory strategiesAndMultipliers =
            new IRewardsCoordinator.StrategyAndMultiplier[](1);
        strategiesAndMultipliers[0] = IRewardsCoordinator.StrategyAndMultiplier({
            strategy: IStrategy(avsManager.BEACON_CHAIN_STRATEGY()),
            multiplier: 1
        });

        vm.warp(1737590400 + 50);
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);
        submissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: strategiesAndMultipliers,
            token: mockERC20,
            operatorRewards: operatorRewards,
            startTimestamp: uint32(block.timestamp - 2 weeks - 50),
            duration: 2 weeks,
            description: "test"
        });

        // Give tokens to AVS manager
        mockERC20.mint(address(avsManager), 1000);

        // Expect approval to be called with correct parameters
        vm.expectCall(address(mockERC20), abi.encodeCall(IERC20.approve, (address(mockRewardsCoordinator), 300)));

        // Expect rewards submission to be called
        vm.expectCall(
            address(mockRewardsCoordinator),
            abi.encodeCall(
                IRewardsCoordinator.createOperatorDirectedAVSRewardsSubmission, (address(avsManager), submissions)
            )
        );

        vm.prank(OPERATIONS_MULTISIG);
        vm.expectEmit();
        emit IUniFiAVSManager.OperatorRewardsSubmitted();
        avsManager.submitOperatorRewards(submissions);
    }

    function testSubmitOperatorRewards_RevertIf_InsufficientBalance() public {
        // Create mock rewards submission data
        IRewardsCoordinator.OperatorReward[] memory operatorRewards = new IRewardsCoordinator.OperatorReward[](1);
        operatorRewards[0] = IRewardsCoordinator.OperatorReward({ operator: address(0x1), amount: 1000 });

        IRewardsCoordinator.StrategyAndMultiplier[] memory strategiesAndMultipliers =
            new IRewardsCoordinator.StrategyAndMultiplier[](1);
        strategiesAndMultipliers[0] = IRewardsCoordinator.StrategyAndMultiplier({
            strategy: IStrategy(avsManager.BEACON_CHAIN_STRATEGY()),
            multiplier: 1
        });
        vm.warp(1737590400 + 50);
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);
        submissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: strategiesAndMultipliers,
            token: mockERC20,
            operatorRewards: operatorRewards,
            startTimestamp: uint32(block.timestamp - 2 weeks - 50),
            duration: 2 weeks,
            description: "test"
        });

        // Give insufficient tokens to AVS manager
        mockERC20.mint(address(avsManager), 500);

        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, address(avsManager), 500, 1000)
        );

        vm.prank(OPERATIONS_MULTISIG);
        avsManager.submitOperatorRewards(submissions);
    }

    function testSubmitOperatorRewards_Unauthorized() public {
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](0);

        vm.prank(operator);
        vm.expectRevert(); // Unauthorized access
        avsManager.submitOperatorRewards(submissions);
    }

    function test_revertConstructor() public {
        vm.expectRevert(IUniFiAVSManager.InvalidEigenPodManagerAddress.selector);
        new UniFiAVSManager(IEigenPodManager(address(0)), IDelegationManager(address(0)), IAVSDirectory(address(0)), IRewardsCoordinator(address(0)));
        vm.expectRevert(IUniFiAVSManager.InvalidEigenDelegationManagerAddress.selector);
        new UniFiAVSManager(IEigenPodManager(address(1)), IDelegationManager(address(0)), IAVSDirectory(address(0)), IRewardsCoordinator(address(0)));
        vm.expectRevert(IUniFiAVSManager.InvalidAVSDirectoryAddress.selector);
        new UniFiAVSManager(IEigenPodManager(address(1)), IDelegationManager(address(1)), IAVSDirectory(address(0)), IRewardsCoordinator(address(0)));
        vm.expectRevert(IUniFiAVSManager.InvalidRewardsCoordinatorAddress.selector);
        new UniFiAVSManager(IEigenPodManager(address(1)), IDelegationManager(address(1)), IAVSDirectory(address(1)), IRewardsCoordinator(address(0)));
    }
}
