# UniFiAVSScripts Usage Guidelines

This document provides guidelines on how to use the UniFiAVSScripts and its functions for interacting with the UniFiAVSManager contract.

## Setup

Before running any scripts, ensure that you have:

1. Added the necessary contract addresses:
   - For Helder chain: UniFiAVSManager, MockEigenPodManager, MockDelegationManager, MockAVSDirectory
   - For other chains (e.g., Holesky, Mainnet): UniFiAVSManager, EigenPodManager, DelegationManager, AVSDirectory
2. Set the correct chain ID for the Helder chain in the setUp function.
3. Created a validators JSON file (if needed for certain functions). You can create this file using the following command:

   ```
    curl -X 'POST' \
    'https://bn.bootnode.helder-devnets.xyz/eth/v1/beacon/states/head/validators' \
    -H 'accept: application/json' \
    -H 'Content-Type: application/json' \
    -d '{
    "ids": ["0x86d7e4912c433fce45b60d499ce538c66e7fd722789d773583d5cdf21a86e28d438630770c45c0e75ee7f50500aa02fc", "0xaed5939124f0ca0ebd99496ac744cafaa0e874fb0a3d0cd63ef93f4d63573f3dca3f56d0e7514567c230dbee95f8bd4c"]
    }' > script/validators.json
   ```

   This command fetches the current validator information from the Helder devnet, filter it by the given list of ids (pubkeys) and saves it to a file named `validators.json`.

## Running Scripts

To run a script, use the following command format:

```
forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "functionName(parameters)" "parameter1" "parameter2" ...
```

Replace `functionName` with the desired function and provide the necessary parameters. To broadcast the script results on-chain you will also need to include flags like `--rpc-url https://rpc.helder-devnets.xyz/ --broadcast --account <your-cast-wallet-name>`. 

## Understanding OperatorCommitment

The OperatorCommitment is a struct that contains two important pieces of information:
1. delegateKey: A bytes array representing the delegate key for the operator.
2. chainIds: A uint256 array of chain IDs the operator is committed to.

## Deregistration Delay

The UniFiAVSManager implements a deregistration delay mechanism for security purposes. This delay is a period that must pass before certain actions (like deregistering an operator or updating commitments) can be completed.

Functions affected by the deregistration delay:
- finishDeregisterOperator(): Can only be called after the delay period since startDeregisterOperator() was called.
- setOperatorCommitment(): Sets into effect the new commitment only after the delay period is passed.

The length of the delay is configurable and can be queried using the getDeregistrationDelay() function.

## Available Functions

### Helder-only Functions

* `createEigenPod(address podOwner)`
   - Creates a mock EigenPod for the specified podOwner.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "createEigenPod(address)" "0x1234..."`

* `delegateFromPodOwner(address podOwner, address operator)`
   - Delegates from PodOwner to Operator using MockDelegationManager.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "delegateFromPodOwner(address,address)" "0x1234..." "0x5678..."`

* `addValidatorsFromJsonFile(string memory filePath, address podOwner)`
   - Adds validators from a JSON file and registers them with UniFiAVSManager.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "addValidatorsFromJsonFile(string,address)" "path/to/validators.json" "0x1234..."`

* `addValidatorsToEigenPodAndRegisterToAVS(address podOwner, bytes[] memory pubkeys, uint64[] memory validatorIndices)`
   - Adds validators directly to EigenPod and registers them with UniFiAVSManager.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "addValidatorsToEigenPodAndRegisterToAVS(address,bytes[],uint64[])" "0x1234..." '["0xpubkey1...","0xpubkey2..."]' '[1,2]'`

* `setupPodAndRegisterValidatorsFromJsonFile(uint256 signerPk, address podOwner, bytes memory delegateKey, string memory filePath)`
   - Sets up a pod and registers validators from a JSON file.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "setupPodAndRegisterValidatorsFromJsonFile(uint256,address,bytes,string)" 123456 "0x1234..." "0xdelegateKey..." "path/to/validators.json"`

* `setupPodAndRegisterValidators(uint256 signerPk, address podOwner, bytes memory delegateKey, bytes[] memory pubkeys, uint64[] memory validatorIndices)`
   - Sets up a pod and registers validators directly.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "setupPodAndRegisterValidators(uint256,address,bytes,bytes[],uint64[])" 123456 "0x1234..." "0xdelegateKey..." '["0xpubkey1...","0xpubkey2..."]' '[1,2]'`

### Common Functions

* `registerValidatorsToUniFiAVS(address podOwner, bytes32[] memory blsPubKeyHashes)`
    - Registers validators with the UniFiAVSManager using pre-hashed public keys.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerValidatorsToUniFiAVS(address,bytes32[])" "0x1234..." '["0xabcd...","0xefgh..."]'`

* `registerValidatorsToUniFiAVS(address podOwner, bytes[] memory pubkeys)`
    - Registers validators with the UniFiAVSManager using raw public keys.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerValidatorsToUniFiAVS(address,bytes[])" "0x1234..." '["0xpubkey1...","0xpubkey2..."]'`

* `registerOperatorToUniFiAVS(uint256 signerPk, OperatorCommitment memory initialCommitment)`
    - Registers an operator with the UniFiAVSManager and sets the initial commitment.
    - The signerPk is used to sign the operator signature for both EOA and EIP-1271 compliant smart contracts:
      - For EOA: The signer address (derived from signerPk) is the same as the operator address.
      - For EIP-1271: The signer can be an EOA (using signerPk) while the operator is a smart contract.
    - Note: When using a smart contract as the operator, it must implement EIP-1271 for signature verification.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVS(uint256,(bytes,uint256))" 123456 '["0xdelegateKey...",42]'`

* `registerOperatorToUniFiAVS(bytes32 signerPk)`
    - Registers an operator with the UniFiAVSManager using hex private key.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVS(bytes32)" 0x123456abcdef...`
    - To verify your operator registration, call the function getOperator(address) like this: 
      `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "getOperator(address)" "OPERATOR_ADDRESS"`


* `registerOperatorToUniFiAVS(uint256 signerPk)`
    - Registers an operator with the UniFiAVSManager using uint256 private key.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVS(uint256)" 123456`
    - To verify your operator registration, call the function getOperator(address) like this: 
      `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "getOperator(address)" "OPERATOR_ADDRESS"`

* `registerOperatorToUniFiAVSWithDelegateKey(uint256 signerPk)`
    - Registers an operator with the UniFiAVSManager using the supplied operator private key to sign the registration message.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVSWithDelegateKey(uint256)" 123456`

* `registerOperatorToUniFiAVSWithDelegateKey(uint256 signerPk, bytes memory delegateKey)`
    - Registers an operator with the UniFiAVSManager using only a delegate key.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVSWithDelegateKey(uint256,bytes)" 123456 "0xdelegateKey..."`
    - To verify your operator registration, call the function getOperator(address) like this: 
      `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "getOperator(address)" "OPERATOR_ADDRESS"`

* `delegateFromPodOwnerBySignature(address staker, address operator, ISignatureUtils.SignatureWithExpiry memory stakerSignatureAndExpiry, ISignatureUtils.SignatureWithExpiry memory approverSignatureAndExpiry, bytes32 approverSalt)`
    - Delegates from PodOwner to Operator by signature.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "delegateFromPodOwnerBySignature(address,address,(bytes,uint256),(bytes,uint256),bytes32)" "0x1234..." "0x5678..." '["0xstakerSignature...",1234567890]' '["0xapproverSignature...",1234567890]' "0xsalt..."`

* `setOperatorCommitment(OperatorCommitment memory newCommitment)`
    - Sets the operator's commitment.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "setOperatorCommitment((bytes,uint256))" '["0xnewDelegateKey...",42]'`
    - Note: This initiates the commitment change process. The new commitment will not be active until the deregistration delay amount of time has passed.

* `startDeregisterOperator()`
    - Starts the process of deregistering an operator.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "startDeregisterOperator()"`
    - Note: This function initiates the deregistration process, which will be completed after the deregistration delay.
    - Important: This function will fail if the operator has not already deregistered all of their validators. Ensure all validators are deregistered before calling this function.

* `finishDeregisterOperator()`
    - Finishes the process of deregistering an operator.
    - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "finishDeregisterOperator()"`
    - Note: This function can only be called after the deregistration delay has passed since startDeregisterOperator() was called.

### Mainnet/Holesky Functions

* `registerAsOperator(IDelegationManager.OperatorDetails memory registeringOperatorDetails, string memory metadataURI)`
   - Registers the caller as an operator in the DelegationManager contract.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerAsOperator((address,address,uint32,uint32,uint96,uint96,bool,uint256[]),string)" '["0xoperatorAddress","0xearningsReceiverAddress",1000,2000,1000000000000000000,2000000000000000000,true,[1,2,3]]' "https://metadata.uri"`

* `delegateFromPodOwner(address operator, ISignatureUtils.SignatureWithExpiry memory approverSignatureAndExpiry, bytes32 approverSalt)`
   - Delegates from PodOwner to Operator with signature.
   - Usage: `forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "delegateFromPodOwner(address,(bytes,uint256),bytes32)" "0x5678..." '["0xsignature...",1234567890]' "0xsalt..."`
