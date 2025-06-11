// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { DeployUniFiToMainnet } from "../../script/DeployUniFiToMainnet.s.sol";
import { UniFiAVSManager } from "../../src/UniFiAVSManager.sol";
import { IUniFiAVSManager } from "../../src/interfaces/IUniFiAVSManager.sol";
import { IRestakingOperator } from "../../src/interfaces/IRestakingOperator.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { AVSDeployment } from "../../script/DeploymentStructs.sol";
import { BaseScript } from "../../script/BaseScript.s.sol";
import { IAccessManaged } from "@openzeppelin/contracts/access/manager/IAccessManaged.sol";

contract UniFiAVSManagerForkTest is Test, BaseScript {
    UniFiAVSManager public avsManager;
    IEigenPodManager public eigenPodManager;
    IDelegationManager public delegationManager;
    IAVSDirectory public avsDirectory;

    // notice the addresses are duplicated here and in the deploy script to ensure they match
    address public constant EIGEN_POD_MANAGER = address(0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338);
    address public constant EIGEN_DELEGATION_MANAGER = address(0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A);
    address public constant AVS_DIRECTORY = address(0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF);
    address public constant MODULE_MANAGER = address(0x9E1E4fCb49931df5743e659ad910d331735C3860);

    address public constant operator = 0x4d7C3fc856AB52753B91A6c9213aDF013309dD25; // Puffer ReOp
    address public constant podOwner = 0xe60cA7AbF24De99aF64e7d9057659aE2dBC2eB2C; // PUFFER_MODULE_0
    uint64 public constant DEREGISTRATION_DELAY = 50400; // Approximately 7 days worth of blocks (assuming ~12 second block time)

    bytes public activeValidatorPubkey = abi.encodePacked(
        hex"8f77ef4427e190559eb6f8f2f4759e88f10deea104da8f8c0925d233192706974c49018abf8310cb8282a93d18fb1c9b"
    );

    bytes public exitedValidatorPubkey = abi.encodePacked(
        hex"90ba70225a0ab658a629431cfc0bde70eb4dc4022e6ab60ac020dea6d9b3ff14a9d17395bd6bfa90c7d999a184a77b33"
    );

    address public operatorSigner;
    uint256 public operatorPrivateKey;

    address public DAO = 0xC0896ab1A8cae8c2C1d27d011eb955Cca955580d;

    function setUp() public virtual {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 20731077); // Replace with an appropriate block number

        (operatorSigner, operatorPrivateKey) = makeAddrAndKey("operatorSigner");

        // Setup contracts that are deployed to mainnet
        eigenPodManager = IEigenPodManager(EIGEN_POD_MANAGER);
        delegationManager = IDelegationManager(EIGEN_DELEGATION_MANAGER);
        avsDirectory = IAVSDirectory(AVS_DIRECTORY);

        // Deploy UniFiAVSManager
        DeployUniFiToMainnet deployScript = new DeployUniFiToMainnet();
        AVSDeployment memory deployment = deployScript.run();

        address avsManagerProxy = deployment.avsManagerProxy;

        avsManager = UniFiAVSManager(payable(avsManagerProxy));
        // Set deregistration delay
        vm.prank(DAO);
        avsManager.setDeregistrationDelay(DEREGISTRATION_DELAY);
    }

    function test_registerAndDeregisterOperator() public {
        // Register operator
        _registerOperator();

        IAVSDirectory.OperatorAVSRegistrationStatus status = _getAvsOperatorStatus();
        assertEq(
            uint256(status),
            uint256(IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED),
            "Operator should be registered"
        );

        // Start deregistration
        vm.prank(operator);
        avsManager.startDeregisterOperator();

        // Try to finish deregistration before delay
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.DeregistrationDelayNotElapsed.selector);
        avsManager.finishDeregisterOperator();

        // Advance block number instead of time
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Finish deregistration
        vm.prank(operator);
        avsManager.finishDeregisterOperator();

        assertEq(
            uint256(_getAvsOperatorStatus()),
            uint256(IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED),
            "Operator should be deregistered"
        );
    }

    function test_registerAndDeregisterValidators() public {
        _registerOperator();

        uint256[] memory initialChainIds = new uint256[](1);
        initialChainIds[0] = 1;

        // Set and update operator commitment
        IUniFiAVSManager.OperatorCommitment memory newCommitment = IUniFiAVSManager.OperatorCommitment({
            delegateKey: abi.encodePacked(operatorSigner),
            chainIds: initialChainIds
        });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Register active validator
        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = activeValidatorPubkey;
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // Attempt to register exited validator (should fail)
        bytes[] memory exitedValidators = new bytes[](1);
        exitedValidators[0] = exitedValidatorPubkey;
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.ValidatorNotActive.selector);
        avsManager.registerValidators(podOwner, exitedValidators);

        // Check registration status
        IUniFiAVSManager.ValidatorDataExtended memory activeValidatorData =
            avsManager.getValidator(activeValidatorPubkey);
        assertTrue(activeValidatorData.registered, "Active validator should be registered");

        IUniFiAVSManager.ValidatorDataExtended memory exitedValidatorData =
            avsManager.getValidator(exitedValidatorPubkey);
        assertFalse(exitedValidatorData.registered, "Exited validator should not be registered");

        // Deregister validators
        vm.prank(operator);
        avsManager.deregisterValidators(activeValidators);

        activeValidatorData = avsManager.getValidator(activeValidatorPubkey);
        assertFalse(activeValidatorData.registered, "Validator should be deregistered");
    }

    function test_registerOperatorWithInvalidSignature() public {
        bytes32 salt = bytes32(uint256(1));
        uint256 expiry = block.timestamp + 1 days;

        // Generate an invalid signature
        (, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) =
            _getOperatorSignature(operator, address(avsManager), salt, expiry);
        operatorSignature.signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        // Attempt to register operator with invalid signature
        bytes memory registerOperatorCallData =
            abi.encodeWithSelector(IUniFiAVSManager.registerOperator.selector, operatorSignature);

        vm.prank(MODULE_MANAGER);
        vm.expectRevert();
        IRestakingOperator(operator).customCalldataCall(address(avsManager), registerOperatorCallData);
    }

    function test_registerValidatorsWithInvalidPodOwner() public {
        _registerOperator();

        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = activeValidatorPubkey;

        // Attempt to register validators with an invalid pod owner
        address invalidPodOwner = address(0x1234);
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.NoEigenPod.selector);
        avsManager.registerValidators(invalidPodOwner, activeValidators);
    }

    function test_deregisterValidatorsWithNonExistentValidator() public {
        _registerOperator();

        bytes[] memory validatorPubkeys = new bytes[](1);
        validatorPubkeys[0] = abi.encodePacked("nonExistentValidator");

        // Attempt to deregister a non-existent validator
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.NotValidatorOperator.selector);
        avsManager.deregisterValidators(validatorPubkeys);
    }

    function test_startDeregisterOperatorWithValidators() public {
        _registerOperator();

        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 1;
        newChainIds[1] = 137;
        IUniFiAVSManager.OperatorCommitment memory newCommitment =
            IUniFiAVSManager.OperatorCommitment({ delegateKey: abi.encodePacked(uint256(1337)), chainIds: newChainIds });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = activeValidatorPubkey;

        // Register validators
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // Attempt to start deregistration with active validators
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.OperatorHasValidators.selector);
        avsManager.startDeregisterOperator();
    }

    function test_finishDeregisterOperatorBeforeDelay() public {
        _registerOperator();

        // Start deregistration
        vm.prank(operator);
        avsManager.startDeregisterOperator();

        // Attempt to finish deregistration before delay
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.DeregistrationDelayNotElapsed.selector);
        avsManager.finishDeregisterOperator();
    }

    function test_setDeregistrationDelayFromUnauthorizedAddress() public {
        vm.prank(operator); // Using operator instead of DAO
        vm.expectRevert(abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, operator));
        avsManager.setDeregistrationDelay(DEREGISTRATION_DELAY); // Attempt to set deregistration delay without authorization
    }

    function test_getOperatorRestakedStrategies() public {
        // Register operator
        _registerOperator();
        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 1;
        newChainIds[1] = 137;
        IUniFiAVSManager.OperatorCommitment memory newCommitment =
            IUniFiAVSManager.OperatorCommitment({ delegateKey: abi.encodePacked(uint256(1337)), chainIds: newChainIds });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Register active validator
        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = activeValidatorPubkey;
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // Get restaked strategies
        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        // Assert
        assertEq(restakedStrategies.length, 1, "Should have one restaked strategy");
        assertEq(restakedStrategies[0], avsManager.BEACON_CHAIN_STRATEGY(), "Should be the Beacon Chain strategy");
    }

    function test_getRestakeableStrategies() public view {
        // Get restakeable strategies
        address[] memory restakeableStrategies = avsManager.getRestakeableStrategies();

        // Assert
        assertEq(restakeableStrategies.length, 1, "Should have one restakeable strategy");
        assertEq(restakeableStrategies[0], avsManager.BEACON_CHAIN_STRATEGY(), "Should be the Beacon Chain strategy");
    }

    function _registerOperator() internal {
        bytes32 salt = bytes32(uint256(1));
        uint256 expiry = block.timestamp + 1 days;

        (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) =
            _getOperatorSignature(operator, address(avsManager), salt, expiry);

        // Update signature proof
        vm.prank(MODULE_MANAGER);
        IRestakingOperator(operator).updateSignatureProof(digestHash, operatorSigner);

        // Register operator
        bytes memory registerOperatorCallData =
            abi.encodeWithSelector(IUniFiAVSManager.registerOperator.selector, operatorSignature);

        vm.prank(MODULE_MANAGER);
        IRestakingOperator(operator).customCalldataCall(address(avsManager), registerOperatorCallData);
    }

    function _getOperatorSignature(address _operator, address avs, bytes32 salt, uint256 expiry)
        internal
        view
        returns (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature)
    {
        operatorSignature.expiry = expiry;
        operatorSignature.salt = salt;
        {
            digestHash = avsDirectory.calculateOperatorAVSRegistrationDigestHash(_operator, avs, salt, expiry);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, digestHash); // Using a dummy private key
            operatorSignature.signature = abi.encodePacked(r, s, v);
        }
        return (digestHash, operatorSignature);
    }

    function _getAvsOperatorStatus() internal view returns (IAVSDirectory.OperatorAVSRegistrationStatus) {
        (bool success, bytes memory data) = address(avsDirectory).staticcall(
            abi.encodeWithSelector(bytes4(keccak256("avsOperatorStatus(address,address)")), avsManager, operator)
        );
        if (!success) {
            revert("AVS operator status call failed");
        }
        return abi.decode(data, (IAVSDirectory.OperatorAVSRegistrationStatus));
    }
}
