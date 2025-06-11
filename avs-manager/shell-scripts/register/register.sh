#!/bin/bash

if [ "$#" -ne 3 ] && [ "$#" -ne 2 ]; then
  echo "Usage: $0 <keystore-file> <password> <rpc-url> or $0 <private-key> <rpc-url>"
  exit 1
fi

if [ "$#" -eq 3 ]; then
  KEYSTORE_FILE=$1
  PASSWORD=$2
  RPC_URL=$3
  if [ ! -f "$KEYSTORE_FILE" ]; then
    echo "Keystore file not found: $KEYSTORE_FILE"
    exit 1
  fi

  PRIVATE_KEY=$(node decryptKeystore.js "$KEYSTORE_FILE" "$PASSWORD")
  if [ $? -ne 0 ]; then
    echo "Failed to execute decryptKeystore.js"
    exit 1
  fi

  if [ -z "$PRIVATE_KEY" ]; then
    echo "Failed to retrieve private key"
    exit 1
  fi
else
  PRIVATE_KEY=$1
  RPC_URL=$2
fi

forge script ../../script/UniFiAVSScripts.sol:UniFiAVSScripts --sig "registerOperatorToUniFiAVS(uint256 signerPk)" $PRIVATE_KEY --private-key $PRIVATE_KEY --rpc-url $RPC_URL --broadcast

# ./register.sh ./test.json 123456 https://rpc.ankr.com/eth [recommended]
# ./register.sh your_private_key https://rpc.ankr.com/eth [not recommended]