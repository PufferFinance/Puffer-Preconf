# Slashing Mechanism

The slashing mechanism in UniFi AVS is designed to ensure the integrity of the pre-confirmation process. It consists of three main cases:

1. Invalid Validator Registration
2. Safety Faults (Breaking Pre-confirmation Promises)
3. Liveness Faults (Missed Block Slashing)

## Invalid Validator Registration
To maintain the integrity of the network, the UniFiAVSManager contract includes several mechanisms to slash operators who register invalid validators. Slashing acts as a deterrent against fraudulent or incorrect registrations.

### Slashing Validators with Invalid Registration Signatures

```solidity
function slashValidatorsWithInvalidSignature(ValidatorRegistrationSlashingParams[] calldata validators) external;
```
Parameters:
- `validators`: An array of `ValidatorRegistrationSlashingParams` structs, each containing the necessary data for slashing.

Example:
```solidity
  ValidatorRegistrationSlashingParams[] memory validators = new ValidatorRegistrationSlashingParams[](1);
  validators[0] = ValidatorRegistrationSlashingParams({
      pubkeyG1: BN254.G1Point({X: 0x1234..., Y: 0x5678...}),
      pubkeyG2: BN254.G2Point({X: [0x9abc..., 0xdef0...], Y: [0x1234..., 0x5678...]}),
      registrationSignature: BN254.G1Point({X: 0x9abc..., Y: 0xdef0...}),
      expiry: block.timestamp + 1 days,
      salt: 123456,
      index: 1 // index of the validator
  });

  uniFiAVSManager.slashValidatorsWithInvalidSignature(validators);
```

Mechanism:
It checks the validity of the registration signature using BLS signature verification. If the signature is found to be invalid, the validator is slashed, and the operator is penalized. This mechanism maintains the authenticity of registrations, ensuring that only legitimate validators are part of the network.

### Slashing Validators with Invalid Index

```solidity
function slashValidatorsWithInvalidIndex(BeaconChainHelperLib.InclusionProof[] calldata proofs) external;
```  
Parameters:
- `proofs`: An array of `BeaconChainHelperLib.InclusionProof` structs, each containing the necessary data for slashing.

Example:

```solidity
  BeaconChainHelperLib.InclusionProof[] memory proofs = new BeaconChainHelperLib.InclusionProof[](1);
  proofs[0] = BeaconChainHelperLib.InclusionProof({
      validator: [0x1234...],
      validatorIndex: 1,
      // Additional proof data...
  });

  uniFiAVSManager.slashValidatorsWithInvalidIndex(proofs);
```

Mechanism:
This function verifies the validator's index against the provided proof. If the index does not match, the validator is slashed. This mechanism prevents the misuse of validator indices, ensuring that each index is unique and correctly assigned.

### Slashing Validators with Invalid Public Key

```solidity
function slashValidatorsWithInvalidPubkey(BeaconChainHelperLib.InclusionProof[] calldata proofs) external;
```
Parameters:
- `proofs`: An array of `BeaconChainHelperLib.InclusionProof` structs, each containing the necessary data for slashing.

Example:
```solidity
  BeaconChainHelperLib.InclusionProof[] memory proofs = new BeaconChainHelperLib.InclusionProof[](1);
  proofs[0] = BeaconChainHelperLib.InclusionProof({
      validator: [0x1234...],
      // Additional proof data...
  });

  uniFiAVSManager.slashValidatorsWithInvalidPubkey(proofs);
```

Mechanism:
Similar to the previous mechanisms, this function verifies the validator's public key against the provided proof. If the public key is found to be invalid, the validator is slashed. This mechanism ensures the integrity of the validator's public key, preventing unauthorized or incorrect registrations.

## Safety Faults (Not Implemented)

Safety faults occur when a validator breaks their pre-conf promise. This category encompasses a larger design space compared to Liveness faults, including:

a) Inclusion Pre-conf Violations:
   - A validator signs a pre-conf with their ECDSA key, committing to include a specific transaction in their block.
   - The validator fails to include the promised transaction in their proposed block.
   - A proof is submitted demonstrating the failure.

b) Execution Pre-conf Violations:
   - A validator commits to executing a transaction with specific pre-conditions or post-conditions.
   - The validator includes the transaction but violates the promised execution conditions.
   - A proof of the violation is submitted.

The larger design space for Safety faults allows for more complex and nuanced slashing conditions, which can be expanded and refined as the pre-confirmation ecosystem evolves.

## Liveness Faults (Not Implemented)

Liveness faults occur when:

1. A validator signs off on pre-confirmations for their upcoming block.
2. The validator fails to submit a block during their assigned slot.
3. A proof is submitted demonstrating that the validator did not propose a block when they were supposed to.

This mechanism ensures that validators cannot abuse the pre-confirmation system by making promises they don't intend to keep due to inactivity.

## Slashing Process for Liveness Faults and Safety Faults

The slashing process involves two key components:

1. DisputeManager: This is where proofs of pre-confirmation violations are submitted. When a violation is detected, anyone can submit a proof to the DisputeManager.

2. EigenLayer Slasher: This is the component responsible for executing the slashing action.

The process works as follows:

1. A proof of either a Safety or Liveness fault is submitted to the DisputeManager.
2. The DisputeManager verifies the validity of the proof.
3. If the proof is valid, the DisputeManager calls `Slasher.freezeOperator()` on EigenLayer.
4. This freezes the operator's stake, preventing them from withdrawing their funds.

It's important to note that as of now, EigenLayer slashing is not fully implemented. The current mechanism only allows for freezing an operator's stake. Full slashing functionality, where a portion of the stake is actually deducted, will be implemented in future updates to EigenLayer.

As EigenLayer's slashing capabilities evolve, UniFi AVS will update its slashing mechanism to take full advantage of these features, potentially including partial stake deductions for violations.

The slashing mechanism is a critical component of UniFi AVS, as it provides strong economic incentives for validators to honor their pre-confirmation commitments and maintain the efficiency and trustworthiness of the system.
