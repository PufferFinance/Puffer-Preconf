# Validator Inclusion Proof Generator

This script generates validator inclusion proofs for the Ethereum beacon chain.

## Setup Instructions

1. Install dependencies:
   ```
   yarn install
   ```

2. Set the Beacon Node URL as an environment variable:
   
   ```
   export BEACON_NODE_URL=https://your-beacon-node-url
   ```

3. Run the script:
   ```
   node validatorProofs.js
   ```

## Usage

The script is currently set up to generate a validator inclusion proof for validator 912203 at slot 9000000. You can modify these values in the `validatorProofs.js` file to generate proofs for different validators and slots.

Example output will be logged to the console, showing the generated inclusion proof.