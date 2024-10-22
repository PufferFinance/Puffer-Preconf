import { getClient } from "@lodestar/api";
import { config } from "@lodestar/config/default";
import { createHash } from "node:crypto";
import { ssz } from "@lodestar/types";
import {
  concatGindices,
  createProof,
  ProofType,
} from "@chainsafe/persistent-merkle-tree";
import BN from "bn.js";

const BeaconState = ssz.deneb.BeaconState;
const BeaconBlock = ssz.deneb.BeaconBlock;

export async function createClient() {
  const beaconNodeUrl = process.env.BEACON_NODE_URL;
  const client = getClient(
    { baseUrl: beaconNodeUrl, timeoutMs: 60_000 },
    { config }
  );

  {
    let r = await client.beacon.getGenesis();
    if (!r.ok) {
      throw r.error;
    }

    client.beacon.genesisTime = r.response.data.genesisTime;
  }

  {
    let r = await client.config.getSpec();
    if (!r.ok) {
      throw r.error;
    }

    client.beacon.secsPerSlot = r.response.data.SECONDS_PER_SLOT;
  }

  client.slotToTS = (slot) => {
    return client.beacon.genesisTime + slot * client.beacon.secsPerSlot;
  };

  return client;
}

// modified version of https://github.com/ethereum/go-ethereum/blob/master/beacon/merkle/merkle.go
export function verifyProofAndGetValidatorsRoot(root, index, proof, value) {
  let buf = value;
  let validatorsRoot;

  proof.forEach((p, i) => {
    const hasher = createHash("sha256");
    if (index % 2n == 0n) {
      hasher.update(buf);
      hasher.update(p);
    } else {
      hasher.update(p);
      hasher.update(buf);
    }
    if (i == 41) {
      validatorsRoot = toHex(buf);
    }
    buf = hasher.digest();
    index >>= 1n;
    if (index == 0n) {
      throw new Error("branch has extra item");
    }
  });

  if (index != 1n) {
    throw new Error("branch is missing items");
  }

  if (toHex(root) != toHex(buf)) {
    throw new Error("proof is not valid");
  }

  return validatorsRoot;
}

export function toHex(t) {
  return "0x" + Buffer.from(t).toString("hex");
}

export function log2(n) {
  return Math.ceil(Math.log2(Number(n))) || 1;
}

export function hexToBuffer(hexStr, length) {
  let str = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
  if (str.length % 2 !== 0) {
    str = "0" + str;
  }
  const buf = Buffer.from(str, "hex");
  if (length && buf.length !== length) {
    throw new Error(`Expected buffer length ${length}, got ${buf.length}`);
  }
  return buf;
}

export function numberToLEBuffer(value, byteLength) {
  const bn = new BN(value.toString(), 10);
  const buf = bn.toArrayLike(Buffer, "le", byteLength);
  return buf;
}

export function validatorToChunks(validator) {
  const chunks = [];

  const zeros16 = Buffer.alloc(16, 0);
  const concatenated = Buffer.concat([
    hexToBuffer(validator.pubkey, 48),
    zeros16,
  ]);
  // chunks[0]: hash of pubkey (Bytes32)
  chunks[0] = "0x" + createHash("sha256").update(concatenated).digest("hex");

  // chunks[1]: withdrawal_credentials (Bytes32)
  let withdrawalBuf = hexToBuffer(validator.withdrawal_credentials, 32);
  chunks[1] = "0x" + withdrawalBuf.toString("hex");

  // chunks[2]: effective_balance (uint64), little-endian, padded to 32 bytes
  let effectiveBalanceBuf = numberToLEBuffer(validator.effective_balance, 8);
  chunks[2] =
    "0x" +
    Buffer.concat([effectiveBalanceBuf, Buffer.alloc(24)]).toString("hex");

  // chunks[3]: slashed (boolean), 1 byte, padded to 32 bytes
  let slashedByte = validator.slashed
    ? Buffer.from([0x01])
    : Buffer.from([0x00]);
  chunks[3] =
    "0x" + Buffer.concat([slashedByte, Buffer.alloc(31)]).toString("hex");

  // chunks[4]: activation_eligibility_epoch (uint64)
  let activationEligibilityEpochBuf = numberToLEBuffer(
    validator.activation_eligibility_epoch,
    8
  );
  chunks[4] =
    "0x" +
    Buffer.concat([activationEligibilityEpochBuf, Buffer.alloc(24)]).toString(
      "hex"
    );

  // chunks[5]: activation_epoch (uint64)
  let activationEpochBuf = numberToLEBuffer(validator.activation_epoch, 8);
  chunks[5] =
    "0x" +
    Buffer.concat([activationEpochBuf, Buffer.alloc(24)]).toString("hex");

  // chunks[6]: exit_epoch (uint64)
  let exitEpochBuf = numberToLEBuffer(validator.exit_epoch, 8);
  chunks[6] =
    "0x" + Buffer.concat([exitEpochBuf, Buffer.alloc(24)]).toString("hex");

  // chunks[7]: withdrawable_epoch (uint64)
  let withdrawableEpochBuf = numberToLEBuffer(validator.withdrawable_epoch, 8);
  chunks[7] =
    "0x" +
    Buffer.concat([withdrawableEpochBuf, Buffer.alloc(24)]).toString("hex");

  return chunks;
}


export async function generateValidatorInclusionProof(slot, validatorIndex) {
  const client = await createClient();

  let r;

  r = await client.debug.getStateV2(slot, "ssz");
  if (!r.ok) {
    throw r.error;
  }

  const stateView = BeaconState.deserializeToView(r.response);

  r = await client.beacon.getBlockV2(slot);
  if (!r.ok) {
    throw r.error;
  }

  const blockView = BeaconBlock.toView(r.response.data.message);
  const blockRoot = blockView.hashTreeRoot();

  const tree = blockView.tree.clone();
  // Patching the tree by attaching the state in the `stateRoot` field of the block.
  tree.setNode(blockView.type.getPropertyGindex("stateRoot"), stateView.node);
  // Create a proof for the state of the validator against the block.
  const gI = concatGindices([
    blockView.type.getPathInfo(["stateRoot"]).gindex,
    stateView.type.getPathInfo(["validators", validatorIndex]).gindex,
  ]);
  const p = createProof(tree.rootNode, { type: ProofType.single, gindex: gI });

  // Sanity check: verify gIndex and proof match.
  const validatorsRoot = verifyProofAndGetValidatorsRoot(
    blockRoot,
    gI,
    p.witnesses,
    stateView.validators.get(validatorIndex).hashTreeRoot()
  );

  // Since EIP-4788 stores parentRoot, we have to find the descendant block of
  // the block from the state.
  r = await client.beacon.getBlockHeaders({ parentRoot: blockRoot });
  if (!r.ok) {
    throw r.error;
  }

  const nextBlock = r.response.data[0]?.header;
  if (!nextBlock) {
    throw new Error("No block to fetch timestamp from");
  }

  const validatorChunks = validatorToChunks(
    stateView.validators.type.elementType.toJson(
      stateView.validators.get(validatorIndex)
    )
  );

  const proofArray = p.witnesses.map(toHex);
  const validatorProof = proofArray.slice(0, 41); // First 41 items
  const beaconStateProof = proofArray.slice(41, 46); // Next 5 items
  const beaconBlockProofForState = proofArray.slice(46, 49); // Next 3 items
  const beaconBlockProofForProposerIndex = [];

  // Construct the InclusionProof object
  const inclusionProof = {
    validator: validatorChunks, // bytes32[8]
    validatorIndex: validatorIndex, // uint256
    validatorProof: validatorProof, // bytes32[]
    validatorsRoot: validatorsRoot, // bytes32
    beaconStateProof: beaconStateProof, // bytes32[]
    beaconStateRoot: toHex(blockView.stateRoot), // bytes32
    beaconBlockProofForState: beaconBlockProofForState, // bytes32[]
    beaconBlockProofForProposerIndex: beaconBlockProofForProposerIndex, // bytes32[]
    timestamp: client.slotToTS(slot), // uint256
  };

  return inclusionProof;
}
