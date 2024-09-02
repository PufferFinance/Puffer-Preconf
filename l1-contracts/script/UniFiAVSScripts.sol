// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { UniFiAVSManager } from "../src/UniFiAVSManager.sol";
import "../src/structs/ValidatorData.sol";
import "../src/structs/OperatorData.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import "../test/mocks/MockEigenPodManager.sol";
import "../test/mocks/MockDelegationManager.sol";
import "../test/mocks/MockAVSDirectory.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";

// to run the script: forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "createEigenPod(address)" "0xabcdefg..."

contract UniFiAVSScripts is Script {
    using Strings for uint256;

    MockDelegationManager mockDelegationManager;
    MockEigenPodManager mockEigenPodManager;
    UniFiAVSManager uniFiAVSManager;

    // update the addresses to the deployed ones
    address mockDelegationManagerAddress = address(123);
    address mockEigenPodManagerAddress = address(123);
    address uniFiAVSManagerAddress = address(123);

    function setUp() public {
        // Initialize the contract instances with their deployed addresses
        mockDelegationManager = MockDelegationManager(mockDelegationManagerAddress);
        mockEigenPodManager = MockEigenPodManager(mockEigenPodManagerAddress);
        uniFiAVSManager = UniFiAVSManager(uniFiAVSManagerAddress);
    }

    // Action 1: Create a Mock Pod
    function createEigenPod(address podOwner) public {
        vm.startBroadcast();
        mockEigenPodManager.createPod(podOwner);
        vm.stopBroadcast();
    }

    // Action 2: Add Validators to MockEigenPod
    function addValidatorsToEigenPod(
        address podOwner,
        bytes32[] memory pubkeyHashes,
        MockEigenPod.ValidatorInfo[] memory validators
    ) public {
        vm.startBroadcast();
        for (uint256 i = 0; i < validators.length; i++) {
            mockEigenPodManager.setValidator(podOwner, pubkeyHashes[i], validators[i]);
        }
        vm.stopBroadcast();
    }

    // Action 3: Register Validators with UniFiAVSManager
    function registerValidatorsToUniFiAVS(address podOwner, bytes32[] memory blsPubKeyHashes) public {
        vm.startBroadcast();
        uniFiAVSManager.registerValidators(podOwner, blsPubKeyHashes);
        vm.stopBroadcast();
    }

    // Action 4: Register an Operator with UniFiAVSManager and set initial commitment (the caller of this script should be the operator)
    function registerOperatorToUniFiAVS(
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature,
        OperatorCommitment memory initialCommitment
    ) public {
        vm.startBroadcast();
        uniFiAVSManager.registerOperator(operatorSignature);
        uniFiAVSManager.setOperatorCommitment(initialCommitment);
        vm.stopBroadcast();
    }

    // Action 5: Delegate from PodOwner to Operator using MockDelegationManager
    function delegateFromPodOwner(address podOwner, address operator) public {
        vm.startBroadcast();
        mockDelegationManager.setDelegation(podOwner, operator);
        vm.stopBroadcast();
    }

    // Action 6: Set the Operator's Commitment
    function setOperatorCommitment(OperatorCommitment memory newCommitment) public {
        vm.startBroadcast();
        uniFiAVSManager.setOperatorCommitment(newCommitment);
        vm.stopBroadcast();
    }

    // Action 7: Update Operator's Commitment
    function updateOperatorCommitment() public {
        vm.startBroadcast();
        uniFiAVSManager.updateOperatorCommitment();
        vm.stopBroadcast();
    }

    // Action 8: Start Deregistering an Operator
    function startDeregisterOperator() public {
        vm.startBroadcast();
        uniFiAVSManager.startDeregisterOperator();
        vm.stopBroadcast();
    }

    // Action 9: Finish Deregistering an Operator
    function finishDeregisterOperator() public {
        vm.startBroadcast();
        uniFiAVSManager.finishDeregisterOperator();
        vm.stopBroadcast();
    }

    // Action 10: Complete Pod Setup and Validator Registration
    function setupPodAndRegisterValidators(
        address podOwner,
        address operator,
        OperatorCommitment memory initialCommitment,
        bytes32[] memory pubkeyHashes,
        MockEigenPod.ValidatorInfo[] memory validators,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) public {
        require(pubkeyHashes.length == validators.length, "Mismatched array lengths");
        vm.startBroadcast();
        // Step 1: Create a Mock Pod
        createEigenPod(podOwner);

        // Step 2: Delegate from PodOwner to Operator
        delegateFromPodOwner(podOwner, operator);

        // Step 3: Register the Operator
        registerOperatorToUniFiAVS(operatorSignature, initialCommitment);

        // Step 4: Add Validators to MockEigenPod
        addValidatorsToEigenPod(podOwner, pubkeyHashes, validators);

        // Step 5: Register Validators with UniFiAVSManager
        registerValidatorsToUniFiAVS(podOwner, pubkeyHashes);
    }

    function addValidatorsFromJsonFile(string memory filePath, address podOwner) public {
        // Read the JSON file as a string
        string memory jsonData = vm.readFile(filePath);

        // Parse the JSON string into a dynamic array of objects
        string[] memory validatorsData = vm.parseJsonStringArray(jsonData, ".data");

        bytes32[] memory pubkeyHashes = new bytes32[](validatorsData.length);
        IEigenPod.ValidatorInfo[] memory validators = new IEigenPod.ValidatorInfo[](validatorsData.length);

        // Iterate over the array and extract the required fields
        for (uint256 i = 0; i < validatorsData.length; i++) {
            // Extract index and pubkey from each object
            string memory validatorJson = validatorsData[i];

            uint256 index = vm.parseJsonUint(validatorJson, ".index");

            bytes memory pubkey = vm.parseJsonBytes(validatorJson, ".validator.pubkey");

            pubkeyHashes[i] = keccak256(pubkey);
            validators[i] = IEigenPod.ValidatorInfo({
                validatorIndex: uint64(index),
                restakedBalanceGwei: 0,
                mostRecentBalanceUpdateTimestamp: 0,
                status: IEigenPod.VALIDATOR_STATUS.ACTIVE
            });

            mockEigenPodManager.setValidator(podOwner, pubkeyHashes[i], validators[i]);

            console.log("Added validator with index:", index);
        }

        uniFiAVSManager.registerValidators(podOwner, pubkeyHashes);
    }
}
