# How to Register as an Operator in UniFi AVS

This guide provides simple steps for operators to register with UniFi AVS.

## Prerequisites

- You have an Operator registered in EigenLayer's contracts ([see guide](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation#goerli-smart-contract-addresses)).
- You have access to an [Ethereum mainnet RPC](https://chainlist.org/).
- You have [Git](https://git-scm.com/downloads) installed.
- You have [Node.js and npm](https://nodejs.org/) installed.
- You have [Yarn](https://yarnpkg.com/getting-started/install) installed.
- You have [Foundry](https://book.getfoundry.sh/getting-started/installation) installed.

## Setup

1. Install Foundry (if not already installed):
   ```
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. Clone the UniFi repository:
   ```
   git clone https://github.com/PufferFinance/UniFi.git
   ```

3. Navigate to the cloned directory:
   ```
   cd UniFi
   ```

4. Install dependencies:
   ```
   yarn install
   ```

5. Navigate to the avs-manager directory:
   ```
   cd avs-manager
   ```

6. Install Foundry dependencies:
   ```
   forge build
   ```

## Phase 1 - Register to UniFi AVS
During phase 1 of UniFi AVS mainnet, Operators can register as follows. Subsequent phases will introduce additional steps such as [registering validators](../registration.md#validator-registration).

1. **Register as an Operator**
   Run the following Solidity script:
   ```
   forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVS(uint256 signerPk)" 'YOUR_OPERATOR_PRIVATE_KEY' --private-key 'YOUR_OPERATOR_PRIVATE_KEY' --rpc-url 'YOUR_MAINNET_RPC_URL' --broadcast 
   ```
   Replace `YOUR_OPERATOR_PRIVATE_KEY` and `YOUR_MAINNET_RPC_URL` with your actual values.

## Verification

To verify your registration:
```
forge script script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "getOperator(address)" "YOUR_OPERATOR_ADDRESS"
```