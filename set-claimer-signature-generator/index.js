import { bls12_381 } from "ethereum-cryptography/bls.js";
import {
  getPublicKeyCoordinates,
  getBlsPubkeyHash,
  getArg,
  getSignatureCoordinates,
  getPublicKeyCoordinatesTuple,
  decryptKeystore,
} from "./utils.js";
import { JsonRpcProvider, Contract, Wallet } from "ethers";
import { UnifiRewardsDistributorAbi } from "./abi.js";
import fs from "fs";
import path from "path";

/**
 * This script is used to generate the signature for the Unifi Rewards Distributor contract
 * Feel free to modify the script to fit your needs.
 *
 * Claimer address: The address of the claimer that will be registered
 * RPC URL: The RPC URL of the network to use (UNIFI L2)
 * Unifi private key: The private key of the Unifi account that will be used to broadcast the transaction (it must have ETH to pay for the gas)
 * Keystore path: The path to the keystore file of the claimer
 * Keystore password: The password of the keystore file. https://github.com/ethereum/staking-deposit-cli was used to create the keystore files. Feel free to use any other tool that is compatible with the spec.
 *
 * `node index.js --claimer <claimer-address> --rpc-url <rpc-url> --unifi-private-key <unifi-private-key> --keystore-path <keystore-path> --password <keystore-password>`
 */
async function main() {
  const args = process.argv.slice(2);

  const claimer = getArg(args, "--claimer");
  const rpcUrl = getArg(args, "--rpc-url");
  const unifiPrivateKey = getArg(args, "--unifi-private-key");
  const keystorePath = getArg(args, "--keystore-path");
  const password = getArg(args, "--password");

  const keystoreFiles = fs
    .readdirSync(keystorePath)
    .filter((file) => file.endsWith(".json"))
    .map((file) => path.join(keystorePath, file));

  const registrationParameters = [];

  const provider = new JsonRpcProvider(rpcUrl);
  const signer = new Wallet(unifiPrivateKey, provider);

  //@todo Update the contract address (UNIFI L2)
  const UnifiRewardsDistributor = new Contract(
    "0x97B954474C220f58Cb99A56d7D9A70368CB4e900",
    UnifiRewardsDistributorAbi,
    signer
  );

  for (const keystoreFile of keystoreFiles) {
    try {
      console.log(`Processing keystore: ${keystoreFile}`);
      const privateKey = await decryptKeystore(keystoreFile, password);

      // Derive public key from the private key
      const publicKey = bls12_381.getPublicKey(privateKey);
      const publicKeyHex = "0x" + Buffer.from(publicKey).toString("hex");

      console.log("Public Key:", publicKeyHex);

      // Get the coordinates of the public key
      const pubkeyG1 = getPublicKeyCoordinates(publicKey);

      // Get the hash of the public key (this Hash is used for the rewards distribution)
      const pubkeyHash = getBlsPubkeyHash(pubkeyG1);

      console.log("Pubkey Hash:", pubkeyHash);

      // Get the message hash that needs to be signed
      const messageHash = await UnifiRewardsDistributor.getMessageHash(
        claimer,
        pubkeyHash
      );

      // Sign the message hash
      // Message hash is 0x prefixed, so we remove the prefix and convert it to hex buffer
      const signature = bls12_381.sign(
        Buffer.from(messageHash.slice(2), "hex"),
        privateKey
      );
      const signatureHex = "0x" + Buffer.from(signature).toString("hex");

      console.log("Signature:", signatureHex);

      const signatureG2 = getSignatureCoordinates(signature);
      const pubKeyTuple = getPublicKeyCoordinatesTuple(publicKey);

      registrationParameters.push({
        signature: signatureG2,
        publicKey: pubKeyTuple,
      });
    } catch (error) {
      console.error(
        `Error processing keystore, skipping: ${keystoreFile}:`,
        error
      );
    }
  }

  // Broadcast the signature to the Unifi Rewards Distributor
  const tx = await UnifiRewardsDistributor.registerClaimer(
    claimer,
    registrationParameters
  );

  console.log("RegisterClaimer transaction hash:", tx.hash);
}

main().catch(console.error);
