// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BN254 } from "eigenlayer-middleware/libraries/BN254.sol";

library BLSSignatureCheckerLib {
    using BN254 for BN254.G1Point;

    function isBlsSignatureValid(
        BN254.G1Point memory pubkeyG1,
        BN254.G2Point memory pubkeyG2,
        BN254.G1Point memory registrationSignature,
        BN254.G1Point memory messageHash
    ) internal view returns (bool) {
        uint256 gamma = uint256(
            keccak256(
                abi.encodePacked(
                    registrationSignature.X,
                    registrationSignature.Y,
                    pubkeyG1.X,
                    pubkeyG1.Y,
                    pubkeyG2.X,
                    pubkeyG2.Y,
                    messageHash.X,
                    messageHash.Y
                )
            )
        ) % BN254.FR_MODULUS;

        // e(sigma + P * gamma, [-1]_2) = e(H(m) + [1]_1 * gamma, P')
        return BN254.pairing(
            registrationSignature.plus(pubkeyG1.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            messageHash.plus(BN254.generatorG1().scalar_mul(gamma)),
            pubkeyG2
        );
    }

    function g1PointToBytes(BN254.G1Point memory point) internal pure returns (bytes memory) {
        bytes memory result = new bytes(48);

        assembly {
            // Store X coordinate
            mstore(add(result, 32), mload(point))

            // Store Y coordinate
            // Set the most significant bit to 1 if Y is odd, 0 if Y is even
            let y := mload(add(point, 32))
            let yMod2 := mod(y, 2)
            y := or(and(y, not(shl(255, 1))), shl(255, yMod2))
            mstore(add(result, 64), y)
        }

        return result;
    }

    function hashG1Point(BN254.G1Point memory pk) internal pure returns (bytes32 hashedG1) {
        return sha256(abi.encodePacked(g1PointToBytes(pk), bytes16(0)));
    }
}
