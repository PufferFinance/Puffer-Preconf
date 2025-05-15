# UniFi Rewards Distributor Makefile
# Use: make <command> [BROADCAST=true]
# Example: make submit-merkle-root BROADCAST=true

# Read environment variables
include .env

# Default values
BROADCAST ?=
DISTRIBUTOR ?= $(CONTRACT_ADDRESS)

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

# Help command
help:
	@echo "UniFi Rewards Distributor Commands:"
	@echo "  make submit-merkle-root [BROADCAST=true]  - Submit a new Merkle root"
	@echo "  make cancel-merkle-root [BROADCAST=true]  - Cancel a pending Merkle root"
	@echo "  make check-merkle-root-status             - Check status of Merkle roots"
	@echo "  make claim-rewards [BROADCAST=true]       - Claim rewards"
	@echo "  make deploy-distributor [BROADCAST=true]  - Deploy a new distributor contract"
	@echo "  make build                                - Build contracts with --via-ir optimization"
	@echo ""
	@echo "Notes:"
	@echo "  - Set BROADCAST=true to broadcast transactions to the network"
	@echo "  - Environment variables are read from the .env file:"
	@echo "    * PK: Private key for transactions"
	@echo "    * RPC_URL: RPC endpoint URL"
	@echo "    * CONTRACT_ADDRESS: UnifiRewardsDistributor contract address"
	@echo "  - You can override CONTRACT_ADDRESS by setting DISTRIBUTOR=<address>"
	@echo "  - All forge commands use --via-ir for optimized code generation" 