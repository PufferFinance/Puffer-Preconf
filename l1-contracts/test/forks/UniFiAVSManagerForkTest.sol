// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import { DeployEverything } from "../../script/DeployEverything.s.sol";
import { UniFiAVSManager } from "../../src/UniFiAVSManager.sol";
import { IUniFiAVSManager } from "../../src/interfaces/IUniFiAVSManager.sol";
import { IRestakingOperator } from "../../src/interfaces/IRestakingOperator.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IAVSDirectoryExtended } from "../../src/interfaces/EigenLayer/IAVSDirectoryExtended.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import "../../src/structs/ValidatorData.sol";
import "../../src/structs/OperatorData.sol";
import { AVSDeployment } from "script/DeploymentStructs.sol";
import { BaseScript } from "script/BaseScript.s.sol";
import { IAccessManaged } from "@openzeppelin/contracts/access/manager/IAccessManaged.sol";

contract UniFiAVSManagerForkTest is Test, BaseScript {
    UniFiAVSManager public avsManager;
    IEigenPodManager public eigenPodManager;
    IDelegationManager public delegationManager;
    IAVSDirectory public avsDirectory;

    address public constant EIGEN_POD_MANAGER = address(0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338);
    address public constant EIGEN_DELEGATION_MANAGER = address(0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A);
    address public constant AVS_DIRECTORY = address(0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF);
    address public constant MODULE_MANAGER = address(0x9E1E4fCb49931df5743e659ad910d331735C3860);

    address public constant operator = 0x4d7C3fc856AB52753B91A6c9213aDF013309dD25; // Puffer ReOp
    address public constant podOwner = 0xe60cA7AbF24De99aF64e7d9057659aE2dBC2eB2C; // PUFFER_MODULE_0
    uint64 public constant DEREGISTRATION_DELAY = 50400; // Approximately 7 days worth of blocks (assuming ~12 second block time)

    bytes32 public activeValidatorPubKeyHash = sha256( // an active validator in the pod
        abi.encodePacked(
            abi.encodePacked(
                hex"8f77ef4427e190559eb6f8f2f4759e88f10deea104da8f8c0925d233192706974c49018abf8310cb8282a93d18fb1c9b"
            ),
            bytes16(0)
        )
    );

    bytes32 public exitedValidatorPubKeyHash = sha256( // an exited validator in the pod
        abi.encodePacked(
            abi.encodePacked(
                hex"90ba70225a0ab658a629431cfc0bde70eb4dc4022e6ab60ac020dea6d9b3ff14a9d17395bd6bfa90c7d999a184a77b33"
            ),
            bytes16(0)
        )
    );

    address public operatorSigner;
    uint256 public operatorPrivateKey;

    address public DAO;

    function setUp() public virtual {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 20731077); // Replace with an appropriate block number

        (operatorSigner, operatorPrivateKey) = makeAddrAndKey("operatorSigner");

        // Setup contracts that are deployed to mainnet
        eigenPodManager = IEigenPodManager(EIGEN_POD_MANAGER);
        delegationManager = IDelegationManager(EIGEN_DELEGATION_MANAGER);
        avsDirectory = IAVSDirectory(AVS_DIRECTORY);

        // Deploy UniFiAVSManager
        DeployEverything deployScript = new DeployEverything();
        AVSDeployment memory avsDeployment =
            deployScript.run(address(eigenPodManager), address(delegationManager), address(avsDirectory));
        DAO = avsDeployment.dao;
        address avsManagerProxy = avsDeployment.avsManagerProxy;

        avsManager = UniFiAVSManager(payable(avsManagerProxy));
        // Set deregistration delay
        vm.prank(DAO);
        avsManager.setDeregistrationDelay(DEREGISTRATION_DELAY);
    }

    function test_registerAndDeregisterOperator() public {
        // Register operator
        _registerOperator();

        IAVSDirectory.OperatorAVSRegistrationStatus status =
            IAVSDirectoryExtended(address(avsDirectory)).avsOperatorStatus(address(avsManager), operator);
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
            uint256(IAVSDirectoryExtended(address(avsDirectory)).avsOperatorStatus(address(avsManager), operator)),
            uint256(IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED),
            "Operator should be deregistered"
        );
    }

    function test_registerAndDeregisterValidators() public {
        _registerOperator();

        // Set and update operator commitment
        OperatorCommitment memory newCommitment = OperatorCommitment({
            delegateKey: abi.encodePacked(operatorSigner),
            chainIDBitMap: 1 // Assuming chainID 1 for mainnet
         });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Update commitment
        vm.prank(operator);
        avsManager.updateOperatorCommitment();

        // Register active validator
        bytes32[] memory activeValidators = new bytes32[](1);
        activeValidators[0] = activeValidatorPubKeyHash;
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // Attempt to register exited validator (should fail)
        bytes32[] memory exitedValidators = new bytes32[](1);
        exitedValidators[0] = exitedValidatorPubKeyHash;
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.ValidatorNotActive.selector);
        avsManager.registerValidators(podOwner, exitedValidators);

        // Check registration status
        ValidatorDataExtended memory activeValidatorData = avsManager.getValidator(activeValidatorPubKeyHash);
        assertTrue(activeValidatorData.registered, "Active validator should be registered");

        ValidatorDataExtended memory exitedValidatorData = avsManager.getValidator(exitedValidatorPubKeyHash);
        assertFalse(exitedValidatorData.registered, "Exited validator should not be registered");

        // Deregister validators
        vm.prank(operator);
        avsManager.deregisterValidators(activeValidators);

        // Check validator status immediately after deregistration
        activeValidatorData = avsManager.getValidator(activeValidatorPubKeyHash);
        assertTrue(activeValidatorData.registered, "Validator should still be registered before delay");

        // Advance block number
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Check validator status after delay
        activeValidatorData = avsManager.getValidator(activeValidatorPubKeyHash);
        assertFalse(activeValidatorData.registered, "Validator should be deregistered after delay");
    }

    function test_updateOperatorCommitment() public {
        _registerOperator();

        OperatorCommitment memory newCommitment =
            OperatorCommitment({ delegateKey: abi.encodePacked(uint256(1337)), chainIDBitMap: 3 });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(
            operatorData.pendingCommitment.delegateKey, newCommitment.delegateKey, "Pending delegate key should match"
        );
        assertEq(
            operatorData.pendingCommitment.chainIDBitMap,
            newCommitment.chainIDBitMap,
            "Pending chainIDBitMap should match"
        );

        // Try to update before delay
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.CommitmentChangeNotReady.selector);
        avsManager.updateOperatorCommitment();

        // Advance block number instead of time
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Update commitment
        vm.prank(operator);
        avsManager.updateOperatorCommitment();

        operatorData = avsManager.getOperator(operator);
        assertEq(operatorData.commitment.delegateKey, newCommitment.delegateKey, "Active delegate key should match");
        assertEq(
            operatorData.commitment.chainIDBitMap, newCommitment.chainIDBitMap, "Active chainIDBitMap should match"
        );
    }

    function test_registerOperatorWithInvalidSignature() public {
        bytes32 salt = bytes32(uint256(1));
        uint256 expiry = block.timestamp + 1 days;

        // Generate an invalid signature
        (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) =
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

        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = activeValidatorPubKeyHash;

        // Attempt to register validators with an invalid pod owner
        address invalidPodOwner = address(0x1234);
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.NoEigenPod.selector);
        avsManager.registerValidators(invalidPodOwner, blsPubKeyHashes);
    }

    function test_deregisterValidatorsWithNonExistentValidator() public {
        _registerOperator();

        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = keccak256(abi.encodePacked("nonExistentValidator"));

        // Attempt to deregister a non-existent validator
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.ValidatorNotFound.selector);
        avsManager.deregisterValidators(blsPubKeyHashes);
    }

    function test_startDeregisterOperatorWithValidators() public {
        _registerOperator();

        OperatorCommitment memory newCommitment =
            OperatorCommitment({ delegateKey: abi.encodePacked(uint256(1337)), chainIDBitMap: 3 });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + DEREGISTRATION_DELAY + 1);

        // Update commitment
        vm.prank(operator);
        avsManager.updateOperatorCommitment();

        bytes32[] memory blsPubKeyHashes = new bytes32[](1);
        blsPubKeyHashes[0] = activeValidatorPubKeyHash;

        // Register validators
        vm.prank(operator);
        avsManager.registerValidators(podOwner, blsPubKeyHashes);

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

    function test_setAndGetChainID() public {
        vm.prank(DAO);
        avsManager.setChainID(1, 1); // Ethereum Mainnet

        uint256 chainID = avsManager.getChainID(1);
        assertEq(chainID, 1, "ChainID should match");
    }

    function test_bitmapToChainIDsWithGaps() public {
        vm.prank(DAO);
        avsManager.setChainID(1, 1); // Ethereum Mainnet
        vm.prank(DAO);
        avsManager.setChainID(3, 137); // Polygon

        uint256 bitmap = 0xA; // 0b1010

        uint256[] memory chainIDs = avsManager.bitmapToChainIDs(bitmap);
        assertEq(chainIDs.length, 2, "Should return 2 chainIDs");
        assertEq(chainIDs[0], 1, "First chainID should match");
        assertEq(chainIDs[1], 137, "Second chainID should match");
    }

    function test_getBitmapIndexForNonExistentChainID() public {
        uint32 nonExistentChainID = 999;

        uint8 index = avsManager.getBitmapIndex(nonExistentChainID);
        assertEq(index, 0, "Bitmap index for non-existent chainID should be 0");
    }

    function test_setChainIDFromUnauthorizedAddress() public {
        vm.prank(operator); // Using operator instead of DAO
        vm.expectRevert(abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, operator));
        avsManager.setChainID(1, 1); // Attempt to set chain ID without authorization
    }

    function test_setDeregistrationDelayFromUnauthorizedAddress() public {
        vm.prank(operator); // Using operator instead of DAO
        vm.expectRevert(abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, operator));
        avsManager.setDeregistrationDelay(DEREGISTRATION_DELAY); // Attempt to set deregistration delay without authorization
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
}
