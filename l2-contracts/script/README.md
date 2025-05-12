# UniFi Reward Scripts

This directory contains scripts for managing rewards in the UniFi protocol.

## PrepareClaimData Script

This script prepares claim data for validators to be used with the ClaimRewards script.

### Usage

```bash
forge script script/PrepareClaimData.s.sol --sig "run(bytes[],uint256[])" \
    "[0x<validator-pubkey-1>, 0x<validator-pubkey-2>, ...]" \
    "[<amount-1>, <amount-2>, ...]"
```

Where:
- `<validator-pubkey-X>` is the BLS public key of the validator
- `<amount-X>` is the total amount earned by the validator (cumulative)

The script will output:
1. The Merkle root
2. A JSON structure with claim data for each validator, including their BLS public key hash, amount, and Merkle proof.

## SubmitMerkleRoot Script

This script allows the contract owner to update the Merkle root on the UnifiRewardsDistributor contract.

### Usage

#### Submit a Merkle Root

```bash
forge script script/SubmitMerkleRoot.s.sol --sig "run(address,bytes32)" \
    <distributor-contract-address> \
    "0x<merkle-root>" \
    --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

#### Submit a Merkle Root from Generated File (No Pre-input Needed)

```bash
# Step 1: View the root from the file
forge script script/SubmitMerkleRoot.s.sol --sig "runFromFile()"

# Step 2: Submit the root using the command provided
```

#### Cancel a Pending Merkle Root

```bash
forge script script/SubmitMerkleRoot.s.sol --sig "cancelPendingRoot(address)" \
    <distributor-contract-address> \
    --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

#### Check Root Status

```bash
forge script script/SubmitMerkleRoot.s.sol --sig "checkRootStatus(address)" \
    <distributor-contract-address> \
    --rpc-url <RPC_URL>
```

## ClaimRewards Script

This script allows a registered claimer to claim rewards for validators they represent.

### Usage

```bash
forge script script/ClaimRewards.s.sol --sig "run(address,bytes32[],uint256[],bytes32[][])" \
    <distributor-contract-address> \
    "[\"0x<bls-pubkey-hash-1>\", \"0x<bls-pubkey-hash-2>\", ...]" \
    "[<amount-1>, <amount-2>, ...]" \
    "[[\"0x<proof-1-element-1>\", \"0x<proof-1-element-2>\", ...], [\"0x<proof-2-element-1>\", ...], ...]" \
    --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

Where:
- `<distributor-contract-address>` is the address of the UnifiRewardsDistributor contract
- `<bls-pubkey-hash-X>` is the hash of the validator's BLS public key
- `<amount-X>` is the total amount earned by the validator (cumulative)
- `<proof-X-element-Y>` are the elements of the Merkle proof for the validator

### Helper Functions

The ClaimRewards script also provides helper functions:

#### Verify Same Claimer

Verifies that all validators in the claim data have the same registered claimer.

```bash
forge script script/ClaimRewards.s.sol --sig "verifySameClaimer(address,bytes32[])" \
    <distributor-contract-address> \
    "[\"0x<bls-pubkey-hash-1>\", \"0x<bls-pubkey-hash-2>\", ...]" \
    --rpc-url <RPC_URL>
```

#### Check Claimable Amounts

Checks how much can be claimed for each validator.

```bash
forge script script/ClaimRewards.s.sol --sig "checkClaimableAmounts(address,bytes32[],uint256[])" \
    <distributor-contract-address> \
    "[\"0x<bls-pubkey-hash-1>\", \"0x<bls-pubkey-hash-2>\", ...]" \
    "[<amount-1>, <amount-2>, ...]" \
    --rpc-url <RPC_URL>
```

## Complete Workflow

1. Run the `PrepareClaimData` script to generate the Merkle root and claim data
   ```bash
   forge script script/PrepareClaimData.s.sol --sig "run(bytes[],uint256[])" \
       "[0x<validator-pubkey-1>, 0x<validator-pubkey-2>, ...]" \
       "[<amount-1>, <amount-2>, ...]"
   ```

2. Submit the Merkle root to the distributor contract
   ```bash
   forge script script/SubmitMerkleRoot.s.sol --sig "runFromFile()" # To view the root
   
   forge script script/SubmitMerkleRoot.s.sol --sig "run(address,bytes32)" \
       <distributor-contract-address> \
       "0x<merkle-root>" \
       --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
   ```

3. Wait for the Merkle root to be activated (check status)
   ```bash
   forge script script/SubmitMerkleRoot.s.sol --sig "checkRootStatus(address)" \
       <distributor-contract-address> \
       --rpc-url <RPC_URL>
   ```

4. Run the `ClaimRewards` script to claim rewards for validators
   ```bash
   forge script script/ClaimRewards.s.sol --sig "run(address,bytes32[],uint256[],bytes32[][])" \
       <distributor-contract-address> \
       "[\"0x<bls-pubkey-hash-1>\", \"0x<bls-pubkey-hash-2>\", ...]" \
       "[<amount-1>, <amount-2>, ...]" \
       "[[\"0x<proof-1-element-1>\", ...], [\"0x<proof-2-element-1>\", ...], ...]" \
       --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
   ``` 