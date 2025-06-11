#!/bin/bash

# Check if BEACON_NODE_URL is set
if [ -z "$BEACON_NODE_URL" ]; then
  echo "Error: BEACON_NODE_URL env var is not set"
  exit 1
fi

# Set SLOT as the first script argument, default to "head" if not provided
SLOT=${1:-head}

# Fetch the beacon header information
# https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader
resp=$(curl -s -X 'GET' "$BEACON_NODE_URL/eth/v1/beacon/headers/$SLOT" -H 'accept: application/json')

# Parse the response using jq
root=$(echo $resp | jq -r '.data.root')
proposer_index=$(echo $resp | jq -r '.data.header.message.proposer_index')
parent_root=$(echo $resp | jq -r '.data.header.message.parent_root')
state_root=$(echo $resp | jq -r '.data.header.message.state_root')
body_root=$(echo $resp | jq -r '.data.header.message.body_root')
slot=$(echo $resp | jq -r '.data.header.message.slot')

# Create a JSON response
json_response=$(jq -nc --arg root "$root" --arg proposer_index "$proposer_index" --arg parent_root "$parent_root" --arg state_root "$state_root" --arg body_root "$body_root" --arg slot "$slot" '{
  block_root: $root,
  body_root: $body_root,
  parent_root: $parent_root,
  proposer_index: $proposer_index,
  state_root: $state_root,
  slot: $slot
}')

# Output the JSON response
echo $json_response