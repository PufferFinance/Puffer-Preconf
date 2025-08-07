// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { Script } from "forge-std/Script.sol";
import { DeployerHelper } from "./DeployerHelper.s.sol";
import { IUniFiAVSManager } from "../src/interfaces/IUniFiAVSManager.sol";
import { ISignatureUtilsMixin } from "eigenlayer/interfaces/ISignatureUtilsMixin.sol";
import { EigenPodManagerMock } from "../test/mocks/EigenPodManagerMock.sol";
import { DelegationManagerMock } from "../test/mocks/DelegationManagerMock.sol";
import { MockAllocationManager } from "../test/mocks/MockAllocationManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { IAllocationManager, IAllocationManagerTypes } from "eigenlayer/interfaces/IAllocationManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IEigenPod, IEigenPodTypes } from "eigenlayer/interfaces/IEigenPod.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IEigenPodManager } from "eigenlayer/interfaces/IEigenPodManager.sol";
import { console } from "forge-std/console.sol";

// to run the script: forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "createEigenPod(address)" "0xabcdefg..."

contract UniFiAVSScripts is Script, DeployerHelper {
    using Strings for uint256;

    address public BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

    // DO NOT CHANGE THE ORDER OF THE STRUCTS BELOW
    // Struct for Validator information
    struct Validator {
        string effective_balance;
        string activation_eligibility_epoch;
        string activation_epoch;
        string exit_epoch;
        bytes pubkey;
        bool slashed;
        string withdrawable_epoch;
        bytes32 withdrawal_credentials;
    }

    // Struct for Data containing validator details
    struct ValidatorData {
        string index;
        Validator validator;
    }

    // Struct for the main object containing execution status, finalized status, and an array of Data
    struct BeaconValidatorData {
        ValidatorData[] data;
        bool execution_optimistic;
        bool finalized;
    }

    IDelegationManager public delegationManager;
    IEigenPodManager public eigenPodManager;
    IUniFiAVSManager public uniFiAVSManager;
    IAllocationManager public allocationManager;

    // update the addresses to the deployed ones
    address public delegationManagerAddress;
    address payable public eigenPodManagerAddress;
    address public uniFiAVSManagerAddress;
    address public allocationManagerAddress;

    bool public isHelderChain;

    function setUp() public {
        isHelderChain = block.chainid == helder;

        allocationManagerAddress = _getAllocationManager();
        eigenPodManagerAddress = payable(_getEigenPodManager());
        delegationManagerAddress = _getEigenDelegationManager();
        // Initialize the contract instances with their deployed addresses
        allocationManager = IAllocationManager(allocationManagerAddress);
        delegationManager = IDelegationManager(_getEigenDelegationManager());
        eigenPodManager = IEigenPodManager(payable(_getEigenPodManager()));
        uniFiAVSManagerAddress = _getUnifyAVSManagerProxy();
        uniFiAVSManager = IUniFiAVSManager(_getUnifyAVSManagerProxy());
    }

    // Helder-only functions

    /// @notice Creates a mock EigenPod for the specified podOwner (Helder only)
    /// @param podOwner The address of the pod owner
    function createEigenPod(address podOwner) public {
        require(isHelderChain, "This function can only be called on the Helder chain");
        vm.startBroadcast();
        EigenPodManagerMock(payable(eigenPodManagerAddress)).createPod(podOwner);
        vm.stopBroadcast();
    }

    /// @notice Adds validators to the MockEigenPod for the specified podOwner (Helder only)
    /// @param podOwner The address of the pod owner
    /// @param pubkeyHashes The hashes of the validator public keys
    /// @param validators The validator information
    function addValidatorsToEigenPod(
        address podOwner,
        bytes32[] memory pubkeyHashes,
        IEigenPodTypes.ValidatorInfo[] memory validators
    ) public {
        require(isHelderChain, "This function can only be called on the Helder chain");
        vm.startBroadcast();
        for (uint256 i = 0; i < validators.length; i++) {
            EigenPodManagerMock(payable(eigenPodManagerAddress)).setValidator(podOwner, pubkeyHashes[i], validators[i]);
        }
        vm.stopBroadcast();
    }

    /// @notice Delegates from PodOwner to Operator using MockDelegationManager (Helder only)
    /// @param podOwner The address of the pod owner
    /// @param operator The address of the operator
    function delegateFromPodOwner(address podOwner, address operator) public {
        require(isHelderChain, "This function can only be called on the Helder chain");
        vm.startBroadcast();
        DelegationManagerMock(payable(delegationManagerAddress)).setIsOperator(operator, true);
        DelegationManagerMock(payable(delegationManagerAddress)).setDelegation(podOwner, operator);
        vm.stopBroadcast();
    }

    /// @notice Adds validators from a JSON file and registers them with UniFiAVSManager (Helder only)
    /// @param filePath The path to the JSON file containing validator data
    /// @param podOwner The address of the pod owner
    function addValidatorsFromJsonFile(string memory filePath, address podOwner) public {
        require(isHelderChain, "This function can only be called on the Helder chain");
        vm.startBroadcast();
        // Read the JSON file as a string
        string memory jsonData = vm.readFile(filePath);
        bytes memory data = vm.parseJson(jsonData);
        BeaconValidatorData memory beaconData = abi.decode(data, (BeaconValidatorData));

        bytes32[] memory pubkeyHashes = new bytes32[](beaconData.data.length);
        bytes[] memory pubkeys = new bytes[](beaconData.data.length);
        IEigenPodTypes.ValidatorInfo[] memory validators = new IEigenPodTypes.ValidatorInfo[](beaconData.data.length);

        // Iterate over the array and extract the required fields
        for (uint256 i = 0; i < beaconData.data.length; i++) {
            // Extract index and pubkey from each object
            ValidatorData memory validatorData = beaconData.data[i];
            uint256 index = _stringToUint(validatorData.index);

            pubkeyHashes[i] = calculateBlsPubKeyHash(validatorData.validator.pubkey);
            pubkeys[i] = validatorData.validator.pubkey;
            validators[i] = IEigenPodTypes.ValidatorInfo({
                validatorIndex: uint64(index),
                restakedBalanceGwei: 0,
                lastCheckpointedAt: 0,
                status: IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
            });

            EigenPodManagerMock(eigenPodManagerAddress).setValidator(podOwner, pubkeyHashes[i], validators[i]);

            console.log("Added validator with index:", index);
        }

        uniFiAVSManager.registerValidators(podOwner, pubkeys);
        vm.stopBroadcast();
    }

    /// @notice Adds validators directly to EigenPod and registers them with UniFiAVSManager (Helder only)
    /// @param podOwner The address of the pod owner
    /// @param pubkeys The public keys of the validators
    /// @param validatorIndices The indices of the validators
    function addValidatorsToEigenPodAndRegisterToAVS(
        address podOwner,
        bytes[] memory pubkeys,
        uint64[] memory validatorIndices
    ) public {
        require(isHelderChain, "This function can only be called on the Helder chain");
        require(pubkeys.length == validatorIndices.length, "Mismatched array lengths");
        vm.startBroadcast();

        bytes32[] memory pubkeyHashes = new bytes32[](pubkeys.length);
        IEigenPodTypes.ValidatorInfo[] memory validators = new IEigenPodTypes.ValidatorInfo[](pubkeys.length);

        for (uint256 i = 0; i < pubkeys.length; i++) {
            pubkeyHashes[i] = calculateBlsPubKeyHash(pubkeys[i]);
            validators[i] = IEigenPodTypes.ValidatorInfo({
                validatorIndex: validatorIndices[i],
                restakedBalanceGwei: 0,
                lastCheckpointedAt: 0,
                status: IEigenPodTypes.VALIDATOR_STATUS.ACTIVE
            });

            EigenPodManagerMock(eigenPodManagerAddress).setValidator(podOwner, pubkeyHashes[i], validators[i]);

            console.log("Added validator with index:", validatorIndices[i]);
        }

        uniFiAVSManager.registerValidators(podOwner, pubkeys);
        vm.stopBroadcast();
    }

    /// @notice Sets up a pod and registers validators from a JSON file (Helder only)
    /// @param podOwner The address of the pod owner
    /// @param filePath The path to the JSON file containing validator data
    function setupPodAndRegisterValidatorsFromJsonFile(
        address podOwner,
        bytes memory delegateKey,
        string memory filePath
    ) public {
        require(isHelderChain, "This function can only be called on the Helder chain");
        // Step 1: Create a Mock Pod
        createEigenPod(podOwner);

        // Step 2: Delegate from PodOwner to Operator
        delegateFromPodOwner(podOwner, msg.sender);

        // Step 3: Register the Operator
        registerOperatorToUniFiAVSWithDelegateKey(delegateKey);

        // Step 4: Add validators to pod and register them to the AVS
        addValidatorsFromJsonFile(filePath, podOwner);
    }

    /// @notice Sets up a pod and registers validators directly (Helder only)
    /// @param podOwner The address of the pod owner
    /// @param pubkeys The public keys of the validators
    /// @param validatorIndices The indices of the validators
    function setupPodAndRegisterValidators(
        address podOwner,
        bytes memory delegateKey,
        bytes[] memory pubkeys,
        uint64[] memory validatorIndices
    ) public {
        require(isHelderChain, "This function can only be called on the Helder chain");

        // Step 1: Create a Mock Pod
        createEigenPod(podOwner);

        // Step 2: Delegate from PodOwner to Operator
        delegateFromPodOwner(podOwner, msg.sender);

        // Step 3: Register the Operator
        registerOperatorToUniFiAVSWithDelegateKey(delegateKey);

        // Step 4: Add validators to pod and register them to the AVS
        addValidatorsToEigenPodAndRegisterToAVS(podOwner, pubkeys, validatorIndices);
    }

    // Non-Helder functions

    /// @notice Delegates from PodOwner to Operator with signature (non-Helder only)
    /// @param operator The address of the operator
    /// @param approverSignatureAndExpiry The approver's signature and expiry
    /// @param approverSalt The approver's salt
    function delegateFromPodOwner(
        address operator,
        ISignatureUtilsMixin.SignatureWithExpiry memory approverSignatureAndExpiry,
        bytes32 approverSalt
    ) public {
        vm.startBroadcast();
        delegationManager.delegateTo(operator, approverSignatureAndExpiry, approverSalt);
        vm.stopBroadcast();
    }

    // Common functions for both Helder and non-Helder chains

    /// @notice Registers validators with the UniFiAVSManager using raw public keys
    /// @param podOwner The address of the pod owner
    /// @param pubkeys The raw public keys of the validators
    function registerValidatorsToUniFiAVS(address podOwner, bytes[] memory pubkeys) public {
        vm.startBroadcast();
        uniFiAVSManager.registerValidators(podOwner, pubkeys);
        vm.stopBroadcast();
    }

    /// @notice Registers an operator with the UniFiAVSManager and sets the initial commitment
    /// @param initialCommitment The initial commitment for the operator
    function registerOperatorToUniFiAVS(IUniFiAVSManager.OperatorCommitment memory initialCommitment)
        public
    {
        IAllocationManagerTypes.RegisterParams memory registerParams = IAllocationManagerTypes.RegisterParams({
            avs: uniFiAVSManagerAddress,
            operatorSetIds: new uint32[](1),
            data: abi.encode(initialCommitment)
        });

        vm.startBroadcast();
        allocationManager.registerForOperatorSets(msg.sender, registerParams);
        uniFiAVSManager.setOperatorCommitment(initialCommitment);
        vm.stopBroadcast();
    }

    /// @notice Registers an operator with the UniFiAVSManager
    function registerOperatorToUniFiAVS() public {
        IAllocationManagerTypes.RegisterParams memory registerParams = IAllocationManagerTypes.RegisterParams({
            avs: uniFiAVSManagerAddress,
            operatorSetIds: new uint32[](1),
            data: new bytes(0)
        });

        vm.startBroadcast();
        allocationManager.registerForOperatorSets(msg.sender, registerParams);
        vm.stopBroadcast();
    }

    /// @notice Registers an operator with the UniFiAVSManager using only a delegate key
    /// @param delegateKey The delegate key for the operator
    function registerOperatorToUniFiAVSWithDelegateKey(bytes memory delegateKey) public {
        IAllocationManagerTypes.RegisterParams memory registerParams = IAllocationManagerTypes.RegisterParams({
            avs: uniFiAVSManagerAddress,
            operatorSetIds: new uint32[](1),
            data: new bytes(0)
        });

        vm.startBroadcast();
        allocationManager.registerForOperatorSets(msg.sender, registerParams);

        uint256[] memory chainIds = new uint256[](1);
        chainIds[0] = 1;

        IUniFiAVSManager.OperatorCommitment memory initialCommitment =
            IUniFiAVSManager.OperatorCommitment({ delegateKey: delegateKey, chainIds: chainIds });

        uniFiAVSManager.setOperatorCommitment(initialCommitment);
        vm.stopBroadcast();
    }

    /// @notice Sets the operator's commitment
    /// @param newCommitment The new commitment for the operator
    function setOperatorCommitment(IUniFiAVSManager.OperatorCommitment memory newCommitment) public {
        vm.startBroadcast();
        uniFiAVSManager.setOperatorCommitment(newCommitment);
        vm.stopBroadcast();
    }

    /// @notice Creates a new operator set and sets it as the current operator set ID
    /// @param operatorSetId The ID for the new operator set
    /// @param strategies Array of strategy addresses to include in the operator set
    function createOperatorSetAndSetCurrent(uint32 operatorSetId, address[] memory strategies) public {
        vm.startBroadcast();
        
        // Convert address array to IStrategy array
        IStrategy[] memory istrategies = new IStrategy[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            istrategies[i] = IStrategy(strategies[i]);
        }
        
        // Create the operator set
        uniFiAVSManager.createOperatorSet(operatorSetId, istrategies);
        
        // Set it as the current operator set ID
        uniFiAVSManager.setCurrentOperatorSetId(operatorSetId);
        
        vm.stopBroadcast();
    }

    /// @notice Creates a new operator set with only the beacon chain strategy and sets it as current
    /// @param operatorSetId The ID for the new operator set
    function createBeaconChainOperatorSetAndSetCurrent(uint32 operatorSetId) public {
        address[] memory strategies = new address[](1);
        strategies[0] = BEACON_CHAIN_STRATEGY;
        createOperatorSetAndSetCurrent(operatorSetId, strategies);
    }

    function _stringToUint(string memory s) internal pure returns (uint256) {
        bytes memory b = bytes(s);
        uint256 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            // Check if the character is a digit (0-9)
            require(b[i] >= 0x30 && b[i] <= 0x39, "Invalid character in string");
            result = result * 10 + (uint256(uint8(b[i])) - 48);
        }
        return result;
    }

    function getOperator(address operator) public view returns (IUniFiAVSManager.OperatorDataExtended memory) {
        return uniFiAVSManager.getOperator(operator);
    }

    /**
     * @dev Internal function to calculate the BLS pubkey hash. It is the same as the one used by EigenLayer.
     * @param validatorPubkey The BLS pubkey
     */
    function calculateBlsPubKeyHash(bytes memory validatorPubkey) public pure returns (bytes32) {
        return sha256(abi.encodePacked(validatorPubkey, bytes16(0)));
    }
}
