# UniFi Rewards Distributor Makefile
# Use: make <command> [BROADCAST=true]
# Example: make submit-merkle-root BROADCAST=true

# Read environment variables
include .env

# Default values
BROADCAST ?=
DISTRIBUTOR ?= $(CONTRACT_ADDRESS)
ACCESS_MANAGER ?= $(ACCESS_MANAGER_ADDRESS)

# Set the default goal to help
.DEFAULT_GOAL := help

# Conditionally set broadcast flag
ifdef BROADCAST
BROADCAST_FLAG = --broadcast
endif

# Anvil RPC URL (can be overriden to use testnet/mainnet)
RPC ?= $(RPC_URL)

# Build step that runs before other forge commands
build:
	@echo "Building contracts with --via-ir optimization..."
	@forge build --via-ir

# Generate Claimer Signatures Command
register-claimer:
	@echo "Generating claimer signatures..."
	@node ../set-claimer-signature-generator/index.js \
	--claimer $(CLAIMER_ADDRESS) \
	--rpc-url $(RPC) \
	--unifi-private-key $(PK) \
	--keystore-path $(KEYSTORE_PATH) \
	--password $(KEYSTORE_PASSWORD)

# Submit Merkle Root Command
submit-merkle-root: build
	@forge script script/SubmitMerkleRoot.s.sol:SubmitMerkleRoot \
	--sig "run(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Cancel Pending Merkle Root Command
cancel-merkle-root: build
	@forge script script/SubmitMerkleRoot.s.sol:SubmitMerkleRoot \
	--sig "cancelPendingRoot(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Check Merkle Root Status Command
check-merkle-root-status: build
	@forge script script/SubmitMerkleRoot.s.sol:SubmitMerkleRoot \
	--sig "checkRootStatus(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK)

# Claim Rewards Command
claim-rewards: build
	@forge script script/ClaimRewards.s.sol:ClaimRewards \
	--sig "run(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Deploy UnifiRewardsDistributor Command
deploy-distributor: build
	@forge script script/DeployUnifiRewardsDistributor.s.sol:DeployUnifiRewardsDistributor \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Grant Merkle Root Poster Role Command
grant-poster-role: build
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantMerkleRootPosterRole(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Grant Merkle Root Canceller Role Command
grant-canceller-role: build
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantMerkleRootCancellerRole(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Grant Funds Rescuer Role Command
grant-rescuer-role: build
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantFundsRescuerRole(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Grant All Roles Command
grant-all-roles: build
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantAllRoles(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PK) \
	$(BROADCAST_FLAG)

# Help command
help:
	@echo "UniFi Rewards Distributor Commands:"
	@echo "  make submit-merkle-root [BROADCAST=true]  - Submit a new Merkle root"
	@echo "  make cancel-merkle-root [BROADCAST=true]  - Cancel a pending Merkle root"
	@echo "  make check-merkle-root-status             - Check status of Merkle roots"
	@echo "  make claim-rewards [BROADCAST=true]       - Claim rewards"
	@echo "  make deploy-distributor [BROADCAST=true]  - Deploy a new distributor contract"
	@echo "  make register-claimer          - Generate signatures for claimer registration"
	@echo "  make grant-poster-role [BROADCAST=true]   - Grant Merkle root poster role"
	@echo "  make grant-canceller-role [BROADCAST=true] - Grant Merkle root canceller role"
	@echo "  make grant-rescuer-role [BROADCAST=true]  - Grant funds rescuer role"
	@echo "  make grant-all-roles [BROADCAST=true]     - Grant all roles (poster, canceller, rescuer)"
	@echo "  make build                                - Build contracts with --via-ir optimization"
	@echo ""
	@echo "Notes:"
	@echo "  - Set BROADCAST=true to broadcast transactions to the network"
	@echo "  - Environment variables are read from the .env file:"
	@echo "    * PK: Private key for transactions"
	@echo "    * RPC_URL: RPC endpoint URL"
	@echo "    * KEYSTORE_PATH: Path to the BLS keystore files"
	@echo "    * KEYSTORE_PASSWORD: Password for the keystore files"
	@echo "    * CONTRACT_ADDRESS: UnifiRewardsDistributor contract address"
	@echo "    * ACCESS_MANAGER_ADDRESS: AccessManager contract address"
	@echo "    * MERKLE_ROOT_POSTER: Address to grant poster role to"
	@echo "    * MERKLE_ROOT_CANCELLER: Address to grant canceller role to"
	@echo "    * FUNDS_RESCUER: Address to grant funds rescuer role to"
	@echo "    * CLAIMER_ADDRESS: Address of the claimer to register"
	@echo "  - You can override CONTRACT_ADDRESS by setting DISTRIBUTOR=<address>"
	@echo "  - You can override ACCESS_MANAGER_ADDRESS by setting ACCESS_MANAGER=<address>"
	@echo "  - All forge commands use --via-ir for optimized code generation" 