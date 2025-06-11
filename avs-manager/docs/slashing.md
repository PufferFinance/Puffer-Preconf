# Slashing Mechanism

The slashing mechanism in UniFi AVS is designed to ensure the integrity of the pre-confirmation process. It consists of two main cases:

1. Safety Faults (Breaking Pre-confirmation Promises)
2. Liveness Faults (Missed Block Slashing)

## Safety Faults

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

## Liveness Faults

Liveness faults occur when:

1. A validator signs off on pre-confirmations for their upcoming block.
2. The validator fails to submit a block during their assigned slot.
3. A proof is submitted demonstrating that the validator did not propose a block when they were supposed to.

This mechanism ensures that validators cannot abuse the pre-confirmation system by making promises they don't intend to keep due to inactivity.

## Slashing Process

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
