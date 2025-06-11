# UniFi Rewards Distributor Makefile
# Use: make <command> PRIVATE_KEY=0x123... [BROADCAST=true]
# Example: make submit-merkle-root PRIVATE_KEY=0x123... BROADCAST=true

# Read environment variables
include .env

# Default values
BROADCAST ?=
DISTRIBUTOR ?= $(CONTRACT_ADDRESS)
ACCESS_MANAGER ?= $(ACCESS_MANAGER_ADDRESS)
PRIVATE_KEY ?=

# Set the default goal to help
.DEFAULT_GOAL := help

# Conditionally set broadcast flag
ifdef BROADCAST
BROADCAST_FLAG = --broadcast
endif

# Anvil RPC URL (can be overriden to use testnet/mainnet)
RPC ?= $(RPC_URL)

# Check if private key is provided
check-private-key:
ifndef PRIVATE_KEY
	$(error PRIVATE_KEY is required. Usage: make <command> PRIVATE_KEY=0x123...)
endif

# Build step that runs before other forge commands
build:
	@echo "Building contracts with --via-ir optimization..."
	@forge build --via-ir

# Generate Claimer Signatures Command
register-claimer: check-private-key
	@echo "Generating claimer signatures..."
	@node ../set-claimer-signature-generator/index.js \
	--claimer $(CLAIMER_ADDRESS) \
	--rpc-url $(RPC) \
	--unifi-private-key $(PRIVATE_KEY) \
	--contract-address $(DISTRIBUTOR) \
	--keystore-path $(KEYSTORE_PATH) \
	--password $(KEYSTORE_PASSWORD)

# Submit Merkle Root Command
submit-merkle-root: build check-private-key
	@forge script script/SubmitMerkleRoot.s.sol:SubmitMerkleRoot \
	--sig "run(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Cancel Pending Merkle Root Command
cancel-merkle-root: build check-private-key
	@forge script script/SubmitMerkleRoot.s.sol:SubmitMerkleRoot \
	--sig "cancelPendingRoot(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Check Merkle Root Status Command
check-merkle-root-status: build
	@forge script script/SubmitMerkleRoot.s.sol:SubmitMerkleRoot \
	--sig "checkRootStatus(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC)

# Claim Rewards Command
claim-rewards: build check-private-key
	@forge script script/ClaimRewards.s.sol:ClaimRewards \
	--sig "run(address)" $(DISTRIBUTOR) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Deploy UnifiRewardsDistributor Command
deploy-distributor: build check-private-key
	@forge script script/DeployUnifiRewardsDistributor.s.sol:DeployUnifiRewardsDistributor \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Grant Merkle Root Poster Role Command
grant-poster-role: build check-private-key
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantMerkleRootPosterRole(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Grant Merkle Root Canceller Role Command
grant-canceller-role: build check-private-key
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantMerkleRootCancellerRole(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Grant Funds Rescuer Role Command
grant-rescuer-role: build check-private-key
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantFundsRescuerRole(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Grant All Roles Command
grant-all-roles: build check-private-key
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "grantAllRoles(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Label All Roles Command
label-all-roles: build check-private-key
	@forge script script/GrantRoles.s.sol:GrantRoles \
	--sig "labelAllRoles(address)" $(ACCESS_MANAGER) \
	--via-ir \
	--rpc-url $(RPC) \
	--private-key $(PRIVATE_KEY) \
	$(BROADCAST_FLAG)

# Help command
help:
	@echo "UniFi Rewards Distributor Commands:"
	@echo "  All commands require PRIVATE_KEY=0x123... as argument"
	@echo ""
	@echo "  make submit-merkle-root PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make cancel-merkle-root PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make check-merkle-root-status             - Check status of Merkle roots"
	@echo "  make claim-rewards PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make deploy-distributor PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make register-claimer PRIVATE_KEY=0x123..."
	@echo "  make grant-poster-role PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make grant-canceller-role PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make grant-rescuer-role PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make grant-all-roles PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make label-all-roles PRIVATE_KEY=0x123... [BROADCAST=true]"
	@echo "  make build                                - Build contracts with --via-ir optimization"
	@echo ""
	@echo "Examples:"
	@echo "  make deploy-distributor PRIVATE_KEY=0x1234567890abcdef... BROADCAST=true"
	@echo "  make grant-all-roles PRIVATE_KEY=0x1234567890abcdef... BROADCAST=true"
	@echo "  make label-all-roles PRIVATE_KEY=0x1234567890abcdef... BROADCAST=true"
	@echo "  make submit-merkle-root PRIVATE_KEY=0x1234567890abcdef... BROADCAST=true"
	@echo ""
	@echo "Environment Variables (.env file):"
	@echo "  - RPC_URL: RPC endpoint URL"
	@echo "  - KEYSTORE_PATH: Path to the BLS keystore files"
	@echo "  - KEYSTORE_PASSWORD: Password for the keystore files"
	@echo "  - CONTRACT_ADDRESS: UnifiRewardsDistributor contract address"
	@echo "  - ACCESS_MANAGER_ADDRESS: AccessManager contract address"
	@echo "  - MERKLE_ROOT_POSTER: Address to grant poster role to"
	@echo "  - MERKLE_ROOT_CANCELLER: Address to grant canceller role to"
	@echo "  - FUNDS_RESCUER: Address to grant funds rescuer role to"
	@echo "  - CLAIMER_ADDRESS: Address of the claimer to register"
	@echo ""
	@echo "Additional Notes:"
	@echo "  - You can override CONTRACT_ADDRESS by setting DISTRIBUTOR=<address>"
	@echo "  - You can override ACCESS_MANAGER_ADDRESS by setting ACCESS_MANAGER=<address>"
	@echo "  - All forge commands use --via-ir for optimized code generation" 