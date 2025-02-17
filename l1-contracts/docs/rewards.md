# Rewards Distribution

The rewards distribution mechanism in UniFi AVS is designed to provide a consistent and attractive incentive structure for participating validators, while addressing the challenges of volatility and infrequent payouts inherent in the pre-confirmation process.

## Key Features

1. **Pre-confirmation Fees**: 
   - Users pay pre-conf fees to validators who commit to including their transactions when proposing a block. 
   - These fees are the primary source of rewards for validators participating in the pre-confirmation process.

2. **Reward Characteristics**: 
   - Volatile: The value of pre-conf fees can fluctuate significantly.
   - Infrequent Payouts: Like block proposals, opportunities to earn pre-conf fees may not occur regularly for individual validators.
   - Economies of Scale: Larger validators or pools may have advantages in capturing these rewards.

3. **MEV-Smoothing**: 
   - Implemented to distribute rewards more evenly over time.
   - This approach helps to mitigate the volatility and infrequency of rewards.
   - Provides validators with a more stable and predictable income stream.

4. **Ether Payouts**: 
   - All rewards are paid out in Ether (ETH).
   - Ensures that validators receive their rewards in Ethereum's native currency.
   - Avoids issues with illiquid or non-native tokens.

5. **Competitive Earnings**: 
   - Validators have the potential to earn consistent and smooth Ether revenue.
   - This revenue stream has the potential to exceed the earnings from today's PBS (Proposer-Builder Separation) pipeline.
   - Creates a compelling economic incentive for validators to participate in the pre-confirmation process.

## Benefits

1. **For Validators**:
   - Potentially higher and more stable earnings compared to standard validation.
   - Additional revenue stream on top of regular validation rewards.
   - Smoother income distribution through MEV-smoothing mechanism.

2. **For the Network**:
   - Encourages widespread adoption of pre-confirmations.
   - Contributes to the overall efficiency and reliability of the Ethereum network.
   - Potentially attracts more validators to the network, enhancing security and decentralization.

3. **For Users**:
   - Faster transaction confirmations through the pre-confirmation process.
   - Potentially lower fees due to increased competition among validators.

This reward structure aims to create a win-win situation for validators and the Ethereum network, promoting the adoption of pre-confirmations and enhancing the overall user experience on Ethereum.


## Claiming the Rewards
1. Rewards are distributed at the end of every 2 weeks where AVS preconfs participation rewards are calculated for each operator per their validators' performance.
   - All the fees accrued during this 2 week period is deposited into the AVS and is distributed to each operator based on the amount of actively participating (registered) validators they had.
   - If an operator has deregistered a validator at any moment during this 2 week window, the operator will not be given any rewards for that particular validator.
   - If a validator missed a block, thus failing to submit the preconf on-chain, then its operator's rewards are penalized. Missing a block invalidates all rewards for that particular validator and it is then removed from the total number of validators. In other words, if a validator missed a block in this 2 week period, it accrues no rewards for the operator.
2. Operators can claim their rewards directly from the EigenLayer app. Alternatively they can also generate the calldata to claim rewards from the EigenLayer Rewards Updater (sidecar) public repository.
   - The rewards will be available once EigenLayer submits the rewards proof on-chain. This usually happens once every 2 weeks, but for latest information refer to their own docs.