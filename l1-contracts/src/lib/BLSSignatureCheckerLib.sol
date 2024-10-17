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
}
