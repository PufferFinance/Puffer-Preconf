import { bls12_381 } from "ethereum-cryptography/bls.js";
import { AbiCoder, keccak256 } from "ethers";
import { decrypt } from "@chainsafe/bls-keystore";
import fs from "fs";

export function getArg(args, flag) {
  const index = args.indexOf(flag);
  if (index === -1 || !args[index + 1]) {
    console.error(`Please provide a value using ${flag} flag`);
    process.exit(1);
  }
  return args[index + 1];
}

function splitBase(x) {
  const hexString = x.toString(16).padStart(128, "0"); // 64 bytes = 128 hex chars
  const highHex = hexString.slice(0, 64); // First 32 bytes
  const lowHex = hexString.slice(64, 128); // Last 32 bytes

  const high = BigInt("0x" + highHex);
  const low = BigInt("0x" + lowHex);

  return { high, low };
}

function serializeG1(xa, xb, ya, yb) {
  return {
    x_a: "0x" + xa.toString(16).padStart(64, "0"),
    x_b: "0x" + xb.toString(16).padStart(64, "0"),
    y_a: "0x" + ya.toString(16).padStart(64, "0"),
    y_b: "0x" + yb.toString(16).padStart(64, "0"),
  };
}

/**
 * Decrypts a keystore file
 * @param {string} keystorePath - The path to the keystore file
 * @param {string} password - The password to decrypt the keystore file
 * @returns {BigInt} The private key
 */
export async function decryptKeystore(keystorePath, password) {
  const keystoreContent = JSON.parse(fs.readFileSync(keystorePath, "utf8"));
  const privateKey = await decrypt(keystoreContent, password);
  return BigInt("0x" + Buffer.from(privateKey).toString("hex"));
}

/**
 * Get the coordinates of a public key
 * @param {string} publicKey - The public key to get the coordinates of, it can be in hex or raw bytes
 * @returns {Object} The coordinates of the public key
 */
export function getPublicKeyCoordinates(publicKey) {
  // Remove 0x prefix if it exists and convert to hex
  if (publicKey.includes("0x")) {
    publicKey = Buffer.from(publicKey.slice(2), "hex");
  }

  const pubKeyAffine =
    bls12_381.G1.ProjectivePoint.fromHex(publicKey).toAffine();
  const pubicKeyX = splitBase(pubKeyAffine.x);
  const pubicKeyY = splitBase(pubKeyAffine.y);
  return serializeG1(
    pubicKeyX.high,
    pubicKeyX.low,
    pubicKeyY.high,
    pubicKeyY.low
  );
}

/**
 * Get the coordinates of a signature
 * @param {string} signature - The signature to get the coordinates of, it can be in hex or raw bytes
 * @returns {Object} The tuple of coordinates of the signature
 */
export function getSignatureCoordinates(signature) {
  const signatureAffine = bls12_381.Signature.fromHex(signature).toAffine();
  const x = signatureAffine.x;
  const y = signatureAffine.y;
  const x1 = splitBase(x.c0);
  const x2 = splitBase(x.c1);
  const y1 = splitBase(y.c0);
  const y2 = splitBase(y.c1);

  return [
    "0x" + x1.high.toString(16).padStart(64, "0"),
    "0x" + x1.low.toString(16).padStart(64, "0"),
    "0x" + x2.high.toString(16).padStart(64, "0"),
    "0x" + x2.low.toString(16).padStart(64, "0"),
    "0x" + y1.high.toString(16).padStart(64, "0"),
    "0x" + y1.low.toString(16).padStart(64, "0"),
    "0x" + y2.high.toString(16).padStart(64, "0"),
    "0x" + y2.low.toString(16).padStart(64, "0"),
  ];
}

/**
 * Get the tuple of coordinates of a public key
 * @param {string} publicKey - The public key to get the tuple of coordinates of, it can be in hex or raw bytes
 * @returns {Object} The tuple of coordinates of the public key
 */
export function getPublicKeyCoordinatesTuple(publicKey) {
  const pubKeyAffine =
    bls12_381.G1.ProjectivePoint.fromHex(publicKey).toAffine();

  const pubicKeyX = splitBase(pubKeyAffine.x);
  const pubicKeyY = splitBase(pubKeyAffine.y);

  return [
    "0x" + pubicKeyX.high.toString(16).padStart(64, "0"),
    "0x" + pubicKeyX.low.toString(16).padStart(64, "0"),
    "0x" + pubicKeyY.high.toString(16).padStart(64, "0"),
    "0x" + pubicKeyY.low.toString(16).padStart(64, "0"),
  ];
}

/**
 * Returns the hash of a BLS public key
 * @param {Object} pubkeyG1 - The coordinates of the public key
 * @returns {string} The hash of the public key
 */
export function getBlsPubkeyHash(pubkeyG1) {
  return keccak256(
    AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [pubkeyG1.x_a, pubkeyG1.x_b, pubkeyG1.y_a, pubkeyG1.y_b]
    )
  );
}
