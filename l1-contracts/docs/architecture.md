
# Overview
UniFi AVS is composed of off-chain software for handling pre-conf operations, and on-chain contracts for handling registrations, rewards, and punishments.

The following diagram highlights how these components interact with each other:
> ![alt text](images/system-overview.png)

## Preconf Flow

The preconf flow in UniFi AVS involves several interactions between different actors:

```mermaid
sequenceDiagram
    autonumber
    participant U as Users
    participant O as Operator
    participant UAM as UniFiAVSManager
    participant G as Gateway
    participant BN as Beacon Node
    participant CB as Commit-Boost
    participant RM as RewardsManager
    participant L1 as Ethereum L1

    O->>UAM: Set delegate key to Gateway
    G->>BN: Query lookahead window
    BN-->>G: Return upcoming proposer indices
    loop For each validator
        G->>UAM: getValidator(validatorIndex)
        UAM-->>G: Validator registration status
    end
    Note over G: confirm Gateway is delegated to
    U->>G: Send transactions to preconf RPC / router
    G-->>U: Return Gateway-signed pre-confs
    CB->>CB: wait for slot...
    CB->>G: Request L1 block
    G-->>CB: Provide L1 block
    CB->>L1: Propose L1 block
    L1->>G: gateway fee
    O->>RM: Claim AVS rewards
```

Here's a detailed description of the preconf flow:

0. **Registration (Not Shown)**: 
    - The `Operator` is assumed to already be [registered](registration.md#operator-registration-process) to the UniFi AVS.

1) **Delegate Key Setup**: 
   - The operator sets their delegate key to point to a Gateway. This allows the Gateway to act on behalf of the operator for preconfirmation duties.

2. **Lookahead Window Request**:
   - The Gateway queries their Beacon node to check the lookahead window 
   
3. **Lookahead Window Response**:
    - The Gateway learns the validator indices of the upcoming proposers.

4. **getValidator call**:
   - For each validator index received, the Gateway queries the UniFiAVSManager contract using the `getValidator` function.

5. **getValidator response**:
   - The contract returns information if the validator is registered on the AVS. The Gateway can confirm that the validator has delegated to them via the `delegateKey` field.

6. **User Transactions**:
   - Users can begin sending transactions to the Gateway via the Gateway's RPC or a Router. 
   
7. **Gateway Response**:
   - The Gateway signs preconfs with their delegate key and returns the signatures to the Users.

8. **Validator Operations**:
    - The validator's Commit-Boost client will wait until the block proposal slot.

9. **L1 Block Request**:
   - When it's time to propose a block, the validator (via Commit-Boost) requests the final L1 block from the Gateway.
   
10. **L1 Block Response**:
   - The Gateway returns an L1 block containing the pre-conf'd transactions.

11. **L1 Block Proposal**:
   - The validator broadcasts the L1 block to the rest of the validators, adding it to the L1 state.

12. **Gateway Reward**:
    - A flat fee is awarded to the Gateway for their coordination services.

13. **AVS Reward**:
    - The rest of the block rewards are deposited into EigenLayer's `RewardsCoordinator` contract. Operators then can claim their rewards from the EigenLayer's interface.

## Rewards Flow

An overview of where the fees originate and where they end up can be seen in the chart below.

> ![alt text](images/rewards-flow.png)

For a comprehensive overview of the rewards distribution system, including its key features, benefits, and impact on the Ethereum ecosystem, see the [Rewards Distribution](rewards.md) document.

The following diagram illustrates the flow of rewards in the UniFi AVS system:

```mermaid
graph TD
    A[User] -->|Pays preconf tips in priority fees| B[Sequencer]
    B -->|Bridges fees back to L1| C[RewardsManager Contract]
    C -->|Distribute rewards| D[Gateway]
    C -->|Distribute rewards| E[AVS]
    F[Rewards Calculator Subgraph] -->|Submit bi-weekly operator rewards| E[AVS]
    E -->|Submit Rewards| G[EigenLayer Rewards Coordinator]
    G -->|Claim reward| H[Operators]
```

## Operator Software
![alt text](images/software-stack.png)
UniFi AVS has a tight coupling with Commit-Boost, allowing validators to seamlessly participate in the preconf process while maintaining their regular validation duties. 

Validators will run Commit-Boost alongside their standard validator stack. At configuration time, the they will register the same `delegateKey` that was set on-chain. This will allow a Gateway to issue preconfs on their behalf.

When it is their turn to propose a block, Commit-Boost will request a complete L1 block from the Gateway and request a signature from the validator similar to the PBS flow today. 

## Smart Contracts
![alt text](images/contracts-overview.png)
### `UniFiAVSManager` - AVS Registrations
#### Operator Registration
At a high level it is required for an `Operator` within the EigenLayer contracts to opt-in to the AVS. See the [Operator Registration Process](registration.md#operator-registration-process) section for more details.

### Operator Commitment Registration
Each `Operator` will register an `OperatorCommitment` containing a `delegateKey` that will be used to issue preconfs and a mapping of supported chainIDs. See the [Delegate Key Registration](registration.md#operator-commitment-registration) section for more details.

#### Validator Registration
If an EigenPod owner has delegated their stake to an `Operator`, then the `Operator` can register the EigenPod's validators as preconferers in the AVS. See the [Validator Registration](registration.md#validator-registration) section for more details.

> **Aside on Neutrality**: In the spirit of neutrality, it is important to keep preconf registrations credibly neutral. As such, the Ethereum community is working to launch a permissionless registry contract that exists outside of any protocols (i.e., outside of Puffer or EigenLayer). To prevent fragmentation, the `UniFiAVSManager` contract will look to this registry as a primary source when validators register, and revert if the validator is not opted-in.

This diagram shows how rewards flow from users through the system, ultimately being distributed to operators, validators, and the gateway.

### `DisputeManager` - Slashing
UniFi AVS implements slashing to ensure the integrity of the preconfirmation process. This mechanism is designed to penalize validators who break their preconfirmation promises or fail to fulfill their duties.

The slashing mechanism consists of two main components:

1. Safety Faults: Penalties for breaking preconfirmation promises.
2. Liveness Faults: Penalties for missing block proposals.
3. Rewards Stealing: Penalties for 'Rug-Pooling'.

```mermaid
graph TD
    A[Validator Signs Pre-confirmation] --> B{Validator Behavior}
    B -->|Breaks Promise| C[Safety Fault]
    B -->|Misses Block Proposal| D[Liveness Fault]
    B -->|Steals MEV| E[Rug Pooling]
    C --> F[Proof Submitted]
    D --> F
    E --> F
    F --> G[Slashing Mechanism Triggered]
    G --> H[Penalize Validator's Restaked Ether]
```

For a detailed explanation of the slashing mechanism, including the types of faults, the slashing process, and future developments, please refer to the [Slashing Mechanism](slashing.md) document.

