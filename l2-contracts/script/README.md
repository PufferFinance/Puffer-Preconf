# UniFi Reward Scripts

This directory contains scripts for managing rewards in the UniFi protocol.

## Setup

### Environment File

Create a `.env` file in the `l2-contracts` directory with the following variables:

```
PK=your_private_key
RPC_URL=your_rpc_endpoint
CONTRACT_ADDRESS=your_distributor_contract_address
ACCESS_MANAGER_ADDRESS=your_access_manager_address
MERKLE_ROOT_POSTER=address_for_poster_role
MERKLE_ROOT_CANCELLER=address_for_canceller_role
FUNDS_RESCUER=address_for_rescuer_role
```

- `PK`: Private key used for transactions
- `RPC_URL`: RPC endpoint URL for the network
- `CONTRACT_ADDRESS`: UnifiRewardsDistributor contract address
- `ACCESS_MANAGER_ADDRESS`: AccessManager contract address
- `MERKLE_ROOT_POSTER`: Address to grant the Merkle root poster role to
- `MERKLE_ROOT_CANCELLER`: Address to grant the Merkle root canceller role to
- `FUNDS_RESCUER`: Address to grant the funds rescuer role to

## Available Commands

The project includes a Makefile with the following commands:

| Command | Description |
|---------|-------------|
| `make help` | Display available commands (default) |
| `make build` | Build contracts with `--via-ir` optimization |
| `make deploy-distributor [BROADCAST=true]` | Deploy a new UnifiRewardsDistributor contract |
| `make grant-poster-role [BROADCAST=true]` | Grant Merkle root poster role |
| `make grant-canceller-role [BROADCAST=true]` | Grant Merkle root canceller role |
| `make grant-rescuer-role [BROADCAST=true]` | Grant funds rescuer role |
| `make grant-all-roles [BROADCAST=true]` | Grant all roles (poster, canceller, rescuer) |
| `make submit-merkle-root [BROADCAST=true]` | Generate and submit a Merkle root from the CSV file |
| `make cancel-merkle-root [BROADCAST=true]` | Cancel a pending Merkle root |
| `make check-merkle-root-status` | Check the status of current and pending Merkle roots |
| `make claim-rewards [BROADCAST=true]` | Claim rewards for validators in the CSV file |

Notes:
- Add `BROADCAST=true` to broadcast transactions to the network
- You can override the distributor address with `DISTRIBUTOR=0x...`
- You can override the access manager address with `ACCESS_MANAGER=0x...`

## CSV Format

The script reads validator data from `script/bls_keys.csv` with the following format:

```
0x93ed1a759289118d6f0f71545574f622769860089bb5e0d5989fa148a38484c780bb4df010677cc12495641a4c6d7d23,0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,2000000000000000000
0xa06ed93c03bdea0f7d6747be3feff5c5ced92b76a576c1712c3b0d049a4eb16a58437ae31f4831a217ff0b34b769a8b2,0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,3000000000000000000
```

Each line contains:
- BLS public key (hex format)
- Token address (use `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` for native ETH)
- Token amount (in wei)

## Complete Workflow

### 1. Deploy the UnifiRewardsDistributor Contract

```bash
# First time setup - deploy a new distributor contract
make deploy-distributor BROADCAST=true

# Take note of the AccessManager and UnifiRewardsDistributor addresses
# Update your .env file with these addresses
```

### 2. Grant Roles to Appropriate Addresses

After deployment, you need to grant roles to addresses that will manage the rewards distribution:

```bash
# Option 1: Grant all roles to addresses specified in .env
make grant-all-roles BROADCAST=true

# Option 2: Grant individual roles
make grant-poster-role BROADCAST=true
make grant-canceller-role BROADCAST=true
make grant-rescuer-role BROADCAST=true
```

You can specify the addresses in the .env file or override them on the command line:
```bash
make grant-all-roles BROADCAST=true ACCESS_MANAGER=0x... MERKLE_ROOT_POSTER=0x... MERKLE_ROOT_CANCELLER=0x... FUNDS_RESCUER=0x...
```

### 3. Registering a Claimer

Before validators can claim rewards, a claimer must be registered for each validator. This is done using the `set-claimer-signature-generator` JavaScript tool.

#### Setup

```bash
# Navigate to the signature generator directory
cd set-claimer-signature-generator

# Install dependencies
yarn install
```

#### Validator Keystores

The script requires validator keystore files that follow the EIP-2335 standard (such as those created by the [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli)). Place these files in a directory:

```
my-validators/
├── keystore-m_12381_3600_0_0_0-1234567890.json
├── keystore-m_12381_3600_0_0_0-0987654321.json
└── ...
```

#### Running the Registration Script

```bash
node index.js \
  --claimer 0xYourClaimerAddress \
  --rpc-url https://your-rpc-endpoint.com \
  --unifi-private-key 0xYourPrivateKey \
  --keystore-path ./my-validators \
  --password YourKeystorePassword
```

Parameters:
- `--claimer` - Ethereum address that will claim rewards (can be a wallet, multisig, or contract)
- `--rpc-url` - RPC endpoint for the UniFi L2 network
- `--unifi-private-key` - Private key with ETH to pay for gas (must be in hex format with 0x prefix)
- `--keystore-path` - Directory containing validator keystore files
- `--password` - Password to decrypt the keystore files

The script will:
1. Load each keystore file from the specified directory
2. Generate a signature authorizing the claimer address
3. Submit a transaction to register the claimer for all validators in one operation

### 4. Prepare Validator Data

Edit the `script/bls_keys.csv` file with your validator BLS public keys and token amounts.

### 5. Submit a Merkle Root

```bash
# Dry run to verify the Merkle root calculation
make submit-merkle-root

# Submit the Merkle root to the blockchain
make submit-merkle-root BROADCAST=true
```

### 6. Check Merkle Root Status

```bash
# Check when the Merkle root will be activated
make check-merkle-root-status
```

### 7. Claim Rewards

```bash
# Dry run to verify the claim process
make claim-rewards

# Claim rewards on the blockchain
make claim-rewards BROADCAST=true
```

### 8. Cancel a Pending Merkle Root (if needed)

```bash
make cancel-merkle-root BROADCAST=true
```

### 9. Rescue Funds (if needed)

If funds need to be rescued from the contract, an address with the FUNDS_RESCUER role can call the rescueFunds function.

All commands use the `--via-ir` optimization flag for better gas efficiency.

## Script Details

### GrantRoles Script

This script allows the owner to grant specific roles to different addresses:

- `grantMerkleRootPosterRole`: Grants the ability to submit new Merkle roots
- `grantMerkleRootCancellerRole`: Grants the ability to cancel pending Merkle roots
- `grantFundsRescuerRole`: Grants the ability to rescue funds from the contract
- `grantAllRoles`: Grants all three roles in a single transaction

### SubmitMerkleRoot Script

This script reads BLS pubkeys and amounts from the CSV file, generates a Merkle root, and submits it to the UnifiRewardsDistributor contract. It also provides functions to cancel pending roots and check root status.

### ClaimRewards Script

This script reads BLS pubkeys and amounts from the CSV file, generates Merkle proofs, and claims rewards for validators. It automatically calculates BLS pubkey hashes and proper proofs.

### DeployUnifiRewardsDistributor Script

This script deploys a new UnifiRewardsDistributor contract and sets up the AccessManager with appropriate function roles. After deployment, you'll need to use the GrantRoles script to assign roles to specific addresses. 