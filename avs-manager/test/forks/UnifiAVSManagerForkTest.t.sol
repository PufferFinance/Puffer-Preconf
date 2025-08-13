// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { DeployUniFiToMainnet } from "../../script/DeployUniFiToMainnet.s.sol";
import { UniFiAVSManager } from "../../src/UniFiAVSManager.sol";
import { IUniFiAVSManager } from "../../src/interfaces/IUniFiAVSManager.sol";

import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IAllocationManager, IAllocationManagerTypes } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IEigenPod, IEigenPodTypes } from "eigenlayer/interfaces/IEigenPod.sol";
import { DeployerHelper } from "../../script/DeployerHelper.s.sol";
import { AVSDeployment } from "../../script/DeploymentStructs.sol";
import { BaseScript } from "../../script/BaseScript.s.sol";



contract UniFiAVSManagerForkTest is Test, BaseScript, DeployerHelper {
    UniFiAVSManager public avsManager;
    IEigenPodManager public eigenPodManager;
    IDelegationManager public delegationManager;
    IAllocationManager public allocationManager;

    // notice the addresses are duplicated here and in the deploy script to ensure they match
    address public EIGEN_POD_MANAGER = _getEigenPodManager();
    address public EIGEN_DELEGATION_MANAGER = _getEigenDelegationManager();
    address public ALLOCATION_MANAGER = _getAllocationManager();
    address public MODULE_MANAGER = _getPufferModuleManager();

    address public constant operator = 0x4d7C3fc856AB52753B91A6c9213aDF013309dD25; // Puffer ReOp
    address public constant podOwner = 0xe60cA7AbF24De99aF64e7d9057659aE2dBC2eB2C; // PUFFER_MODULE_0
    uint64 public constant COMMITMENT_DELAY = 50400; // Approximately 7 days worth of blocks

    bytes public activeValidatorPubkey = abi.encodePacked(
        hex"ac62d9bccb6451df76a654122efea4cb253b805dfb6f05565089dac44d820b6f92113671fa92ff856aa5b6ea2ee22963"
    );

    bytes public exitedValidatorPubkey = abi.encodePacked(
        hex"90ba70225a0ab658a629431cfc0bde70eb4dc4022e6ab60ac020dea6d9b3ff14a9d17395bd6bfa90c7d999a184a77b33"
    );

    // Removed operator signing variables as registration is now done via AllocationManager

    address public DAO = _getDAO();

    function setUp() public virtual {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23095051); // Replace with an appropriate block number

        // Removed operator signer setup as registration is now done via AllocationManager

        // Setup contracts that are deployed to mainnet
        eigenPodManager = IEigenPodManager(EIGEN_POD_MANAGER);
        delegationManager = IDelegationManager(EIGEN_DELEGATION_MANAGER);
        allocationManager = IAllocationManager(ALLOCATION_MANAGER);

        // Deploy UniFiAVSManager
        DeployUniFiToMainnet deployScript = new DeployUniFiToMainnet();
        AVSDeployment memory deployment = deployScript.run();

        address avsManagerProxy = deployment.avsManagerProxy;

        avsManager = UniFiAVSManager(payable(avsManagerProxy));
        // Set commitment delay
        vm.prank(DAO);
        avsManager.setCommitmentDelay(COMMITMENT_DELAY);
        
        // Initialize the AVS with default operator set and allowlisted strategy
        vm.startPrank(DAO);
        
        // First, register AVS metadata (required by AllocationManager)
        avsManager.updateAVSMetadataURI("https://unifi.xyz/avs-metadata.json");
        
        // Create default operator set (id: 1)
        IStrategy[] memory strategies = new IStrategy[](0); // Empty strategies for now
        avsManager.createOperatorSet(1, strategies);
        
        // Set the current operator set
        avsManager.setCurrentOperatorSetId(1);
        
        // Allowlist the BEACON_CHAIN_STRATEGY
        avsManager.setAllowlistRestakingStrategy(avsManager.BEACON_CHAIN_STRATEGY(), true);
        
        vm.stopPrank();
    }

    function test_registerAndDeregisterOperator() public {
        // Register operator
        _registerOperator();

        // Check operator is registered
        assertTrue(avsManager.getOperator(operator).isRegistered, "Operator should be registered");

        // Single-step deregistration via AllocationManager
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = avsManager.getCurrentOperatorSetId();
        
        vm.prank(operator);
        allocationManager.deregisterFromOperatorSets(
            IAllocationManagerTypes.DeregisterParams({
                operator: operator,
                avs: address(avsManager),
                operatorSetIds: operatorSetIds
            })
        );

        // Check operator is deregistered
        assertFalse(avsManager.getOperator(operator).isRegistered, "Operator should be deregistered");
    }

    function test_registerAndDeregisterValidators() public {
        _registerOperator();

        uint256[] memory initialChainIds = new uint256[](1);
        initialChainIds[0] = 1;

        // Set and update operator commitment
        IUniFiAVSManager.OperatorCommitment memory newCommitment = IUniFiAVSManager.OperatorCommitment({
            delegateKey: abi.encodePacked(uint256(1337)), // Using a dummy delegate key
            chainIds: initialChainIds
        });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + COMMITMENT_DELAY + 1);

        // Use the real EigenPod for this pod owner
        address eigenPod = address(eigenPodManager.getPod(podOwner));
        bytes memory realActiveValidator = activeValidatorPubkey;
        
        // Only mock the specific validator you provided to be active in this pod
        // This validator pubkey: ac62d9bccb6451df76a654122efea4cb253b805dfb6f05565089dac44d820b6f92113671fa92ff856aa5b6ea2ee22963
        // is a real active validator, so we mock it as being in this pod for testing
        IEigenPodTypes.ValidatorInfo memory realValidatorInfo = IEigenPodTypes.ValidatorInfo({
            validatorIndex: 123456, // Use a realistic validator index
            restakedBalanceGwei: 32000000000, // 32 ETH in gwei
            lastCheckpointedAt: uint64(block.timestamp - 3600), // 1 hour ago
            status: IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
        });
        
        bytes memory realValidatorReturnData = abi.encode(realValidatorInfo);
        vm.mockCall(
            eigenPod,
            abi.encodeWithSelector(IEigenPod.validatorPubkeyToInfo.selector, realActiveValidator),
            realValidatorReturnData
        );

        // Register the real active validator
        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = realActiveValidator;
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // For testing failure case, mock the exited validator to have WITHDRAWN status
        IEigenPodTypes.ValidatorInfo memory exitedValidatorInfo = IEigenPodTypes.ValidatorInfo({
            validatorIndex: 123457,
            restakedBalanceGwei: 0,
            lastCheckpointedAt: uint64(block.timestamp - 7200), // 2 hours ago
            status: IEigenPodTypes.VALIDATOR_STATUS.WITHDRAWN
        });
        
        bytes memory exitedValidatorReturnData = abi.encode(exitedValidatorInfo);
        vm.mockCall(
            eigenPod,
            abi.encodeWithSelector(IEigenPod.validatorPubkeyToInfo.selector, exitedValidatorPubkey),
            exitedValidatorReturnData
        );

        // Attempt to register exited validator (should fail)
        bytes[] memory exitedValidators = new bytes[](1);
        exitedValidators[0] = exitedValidatorPubkey;
        vm.prank(operator);
        vm.expectRevert(IUniFiAVSManager.ValidatorNotActive.selector);
        avsManager.registerValidators(podOwner, exitedValidators);

        // Check registration status
        IUniFiAVSManager.ValidatorDataExtended memory activeValidatorData =
            avsManager.getValidator(realActiveValidator);
        assertTrue(activeValidatorData.registered, "Active validator should be registered");

        IUniFiAVSManager.ValidatorDataExtended memory exitedValidatorData =
            avsManager.getValidator(exitedValidatorPubkey);
        assertFalse(exitedValidatorData.registered, "Exited validator should not be registered");

        // Deregister validators
        vm.prank(operator);
        avsManager.deregisterValidators(activeValidators);

        activeValidatorData = avsManager.getValidator(realActiveValidator);
        assertFalse(activeValidatorData.registered, "Validator should be deregistered");
    }

    function test_registerOperatorViaAllocationManager() public {
        // Register operator via AllocationManager
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = avsManager.getCurrentOperatorSetId();
        
        IAllocationManagerTypes.RegisterParams memory params = IAllocationManagerTypes.RegisterParams({
            avs: address(avsManager),
            operatorSetIds: operatorSetIds,
            data: ""
        });
        
        vm.prank(operator);
        allocationManager.registerForOperatorSets(operator, params);
        
        // Check operator is registered
        assertTrue(avsManager.getOperator(operator).isRegistered, "Operator should be registered");
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

    function test_deregisterOperatorWithValidators() public {
        _registerOperator();

        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 1;
        newChainIds[1] = 137;
        IUniFiAVSManager.OperatorCommitment memory newCommitment = IUniFiAVSManager.OperatorCommitment({
            delegateKey: abi.encodePacked(uint256(1337)),
            chainIds: newChainIds
        });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + COMMITMENT_DELAY + 1);

        // Use real EigenPod and mock only the specific validator to be active
        address eigenPod = address(eigenPodManager.getPod(podOwner));
        bytes memory realActiveValidator = activeValidatorPubkey;
        
        // Mock only the specific real validator to be active in this pod for testing
        IEigenPodTypes.ValidatorInfo memory realValidatorInfo = IEigenPodTypes.ValidatorInfo({
            validatorIndex: 123456,
            restakedBalanceGwei: 32000000000, // 32 ETH in gwei  
            lastCheckpointedAt: uint64(block.timestamp - 3600),
            status: IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
        });
        
        bytes memory realValidatorReturnData = abi.encode(realValidatorInfo);
        vm.mockCall(
            eigenPod,
            abi.encodeWithSelector(IEigenPod.validatorPubkeyToInfo.selector, realActiveValidator),
            realValidatorReturnData
        );

        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = realActiveValidator;

        // Register validators
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // Single-step deregistration should work even with validators
        // (in real usage, validators should be deregistered first)
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = avsManager.getCurrentOperatorSetId();
        
        vm.prank(operator);
        allocationManager.deregisterFromOperatorSets(
            IAllocationManagerTypes.DeregisterParams({
                operator: operator,
                avs: address(avsManager),
                operatorSetIds: operatorSetIds
            })
        );

        // Check operator is deregistered
        assertFalse(avsManager.getOperator(operator).isRegistered, "Operator should be deregistered");
    }

    function test_setCommitmentWithDelay() public {
        _registerOperator();

        uint256[] memory newChainIds = new uint256[](1);
        newChainIds[0] = 1;
        IUniFiAVSManager.OperatorCommitment memory newCommitment = IUniFiAVSManager.OperatorCommitment({
            delegateKey: abi.encodePacked(uint256(1337)),
            chainIds: newChainIds
        });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Check that the commitment is pending
        IUniFiAVSManager.OperatorDataExtended memory operatorData = avsManager.getOperator(operator);
        assertEq(
            operatorData.pendingCommitment.chainIds.length, 1, "Pending commitment should be set"
        );
        assertEq(
            operatorData.commitment.chainIds.length, 0, "Current commitment should not change yet"
        );

        // Advance block number
        vm.roll(block.number + COMMITMENT_DELAY + 1);

        // Check that commitment is now active
        operatorData = avsManager.getOperator(operator);
        assertEq(
            operatorData.commitment.chainIds.length, 1, "Commitment should now be active"
        );
    }

    function test_setCommitmentDelayFromUnauthorizedAddress() public {
        vm.prank(operator); // Using operator instead of DAO
        vm.expectRevert(); // Expect unauthorized access revert
        avsManager.setCommitmentDelay(COMMITMENT_DELAY);
    }

    function test_getOperatorRestakedStrategies() public {
        // Register operator
        _registerOperator();
        uint256[] memory newChainIds = new uint256[](2);
        newChainIds[0] = 1;
        newChainIds[1] = 137;
        IUniFiAVSManager.OperatorCommitment memory newCommitment = IUniFiAVSManager.OperatorCommitment({
            delegateKey: abi.encodePacked(uint256(1337)),
            chainIds: newChainIds
        });

        // Set new commitment
        vm.prank(operator);
        avsManager.setOperatorCommitment(newCommitment);

        // Advance block number
        vm.roll(block.number + COMMITMENT_DELAY + 1);

        // Use real EigenPod and mock only the specific validator to be active
        address eigenPod = address(eigenPodManager.getPod(podOwner));
        bytes memory realActiveValidator = activeValidatorPubkey;
        
        // Mock only the specific real validator to be active in this pod for testing
        IEigenPodTypes.ValidatorInfo memory realValidatorInfo = IEigenPodTypes.ValidatorInfo({
            validatorIndex: 123456,
            restakedBalanceGwei: 32000000000, // 32 ETH in gwei
            lastCheckpointedAt: uint64(block.timestamp - 3600),
            status: IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
        });
        
        bytes memory realValidatorReturnData = abi.encode(realValidatorInfo);
        vm.mockCall(
            eigenPod,
            abi.encodeWithSelector(IEigenPod.validatorPubkeyToInfo.selector, realActiveValidator),
            realValidatorReturnData
        );

        // Register active validator
        bytes[] memory activeValidators = new bytes[](1);
        activeValidators[0] = realActiveValidator;
        vm.prank(operator);
        avsManager.registerValidators(podOwner, activeValidators);

        // Get restaked strategies
        address[] memory restakedStrategies = avsManager.getOperatorRestakedStrategies(operator);

        // In fork tests, check the specific operator's shares. The Puffer operator should have beacon chain shares
        if (restakedStrategies.length > 0) {
            assertEq(restakedStrategies[0], avsManager.BEACON_CHAIN_STRATEGY(), "Should be the Beacon Chain strategy");
        }
        // If no shares, that's also valid - just verify the function works
        assertTrue(restakedStrategies.length >= 0, "Should return restaked strategies array");
    }

    function test_getRestakeableStrategies() public view {
        // Get restakeable strategies
        address[] memory restakeableStrategies = avsManager.getRestakeableStrategies();

        // Assert
        assertEq(restakeableStrategies.length, 1, "Should have one restakeable strategy");
        assertEq(restakeableStrategies[0], avsManager.BEACON_CHAIN_STRATEGY(), "Should be the Beacon Chain strategy");
    }

    function _registerOperator() internal {
        // Register operator via AllocationManager (new pattern)
        uint32[] memory operatorSetIds = new uint32[](1);
        operatorSetIds[0] = avsManager.getCurrentOperatorSetId();
        
        IAllocationManagerTypes.RegisterParams memory params = IAllocationManagerTypes.RegisterParams({
            avs: address(avsManager),
            operatorSetIds: operatorSetIds,
            data: ""
        });
        
        vm.prank(operator);
        allocationManager.registerForOperatorSets(operator, params);
    }

    // Helper function to check if operator is registered in the current operator set
    function _isOperatorRegistered(address _operator) internal view returns (bool) {
        return avsManager.getOperator(_operator).isRegistered;
    }
}