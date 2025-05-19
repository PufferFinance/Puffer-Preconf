// SPDX-License-Identifier: MIT
// solhint-disable max-line-length
pragma solidity ^0.8.24;

import { BLS } from "../../src/library/BLS.sol";

/// @title BLSG1Decompressor
/// @notice Utility functions for turning the 48-byte compressed form that
///         Ethereum consensus clients use for BLS12-381 G1 public keys into
///         the 4×32-byte representation consumed by the BLS.sol precompiles.
///
///         The algorithm implemented here is the one described in the
///         draft-IETF BLS signature spec and the Eth-staking spec.
///         Steps:
///          1. parse flag bits (compression/∞/y-sign) from the first byte.
///          2. clear the flag bits to obtain the 48-byte x-coordinate.
///          3. compute rhs = x³ + 4 (mod p) and y = rhs^{(p+1)/4}.
///          4. flip y to p−y if its LSB does not match the sign flag.
///          5. left-pad x and y with 16 zero bytes so they fit the 64-byte
///             big-endian layout expected by BLS.G1Point.
library BLSG1Decompressor {
    // Address of the generic modexp precompile (EIP-198)
    uint256 private constant MODEXP_PRECOMPILE = 0x05;

    // BLS12-381 base-field modulus split in two 32-byte limbs (big-endian)
    uint256 private constant P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // Exponent (p+1)/4 used for Tonelli–Shanks shortcut because p ≡ 3 mod 4
    uint256 private constant EXP_HI = 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35;
    uint256 private constant EXP_LO = 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;

    /// @dev Decompress a 48-byte BLS12-381 G1 point.
    /// @param compressed 48-byte, beacon-chain-style compressed public key
    /// @return point     Uncompressed point arranged for BLS.sol
    function decompressG1(bytes calldata compressed) internal view returns (BLS.G1Point memory) {
        require(compressed.length == 48, "BLS: invalid length");

        // 1. ─── Pull flags ---------------------------------------------------
        uint8 indicator = uint8(compressed[0]);
        require(indicator & 0x80 == 0x80, "BLS: bad form"); // compression flag must be 1
        require(indicator & 0x40 == 0x00, "BLS: infinity"); // we do not handle ∞
        uint8 ySign = (indicator & 0x20) >> 5; // 0 => even, 1 => odd

        // 2. ─── Clear the three MSB bits to get the raw x coordinate ---------
        bytes memory x = new bytes(48);
        for (uint256 i = 0; i < 48; ++i) {
            x[i] = compressed[i];
        }
        x[0] = bytes1(indicator & 0x1f);

        // 3. ─── Compute rhs = x³ + 4 (mod p) ---------------------------------
        bytes memory rhs = _computeRhs(x);

        // 4. ─── Square-root rhs via rhs^{(p+1)/4} ---------------------------
        bytes memory y = _modexp(rhs, _exp(), _prime());

        // Decide between y and -y depending on the sign flag (lexicographic).
        bytes memory yNeg = _subMod(_prime(), y);
        (uint256 yHi, uint256 yLo) = _splitWords(y);
        (uint256 nyHi, uint256 nyLo) = _splitWords(yNeg);
        bool yIsLess = _lt(yHi, yLo, nyHi, nyLo);
        // yLess==true means y < -y lexicographically.
        if (ySign == 1) {
            // need lexicographically larger
            if (yIsLess) {
                y = yNeg;
            }
        } else {
            // need lexicographically smaller
            if (!yIsLess) {
                y = yNeg;
            }
        }

        // 5. ─── Pack into BLS.G1Point struct ---------------------------------
        (bytes32 xa, bytes32 xb) = _split64(_pad64(x));
        (bytes32 ya, bytes32 yb) = _split64(y);
        return BLS.G1Point({ x_a: xa, x_b: xb, y_a: ya, y_b: yb });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Internal helpers (minimal and not constant-time — use off-chain whenever
    // possible). All operate on 64-byte big-endian byte arrays lying in memory.
    // ──────────────────────────────────────────────────────────────────────────

    function _computeRhs(bytes memory x) private view returns (bytes memory) {
        bytes memory xCubed = _modexp(_pad64(x), abi.encodePacked(uint8(3)), _prime());
        bytes memory rhs = _addModConst(xCubed, 4);
        return rhs;
    }

    function _pad64(bytes memory b48) private pure returns (bytes memory out) {
        // Left-pad 16 zero bytes so length becomes 64
        out = new bytes(64);
        for (uint256 i = 0; i < 48; ++i) {
            out[i + 16] = b48[i];
        }
    }

    function _split64(bytes memory be64) private pure returns (bytes32 hi, bytes32 lo) {
        assembly {
            hi := mload(add(be64, 32))
            lo := mload(add(be64, 64))
        }
    }

    // prime modulus as 64-byte BE array
    function _prime() private pure returns (bytes memory p) {
        p = new bytes(64);
        assembly {
            mstore(add(p, 32), P_HI)
            mstore(add(p, 64), P_LO)
        }
    }

    // (p+1)/4 exponent as 64-byte BE array
    function _exp() private pure returns (bytes memory e) {
        e = new bytes(64);
        assembly {
            mstore(add(e, 32), EXP_HI)
            mstore(add(e, 64), EXP_LO)
        }
    }

    // Call EIP-198 modexp precompile
    function _modexp(bytes memory base, bytes memory e, bytes memory modn) private view returns (bytes memory ret) {
        uint256 blen = base.length;
        uint256 elen = e.length;
        uint256 mlen = modn.length;
        bytes memory input = new bytes(96 + blen + elen + mlen);
        assembly {
            let ptr := add(input, 32)
            mstore(ptr, blen)
            mstore(add(ptr, 32), elen)
            mstore(add(ptr, 64), mlen)
            let offset := add(ptr, 96)
            // copy base | exp | mod into the buffer ----------------------------------
            calldatacopy(0, 0, 0) // NO-OP just to silence compiler warnings on calldata
            // base
            for { let i := 0 } lt(i, blen) { i := add(i, 32) } { mstore(add(offset, i), mload(add(base, add(32, i)))) }
            offset := add(offset, blen)
            // exp
            for { let i := 0 } lt(i, elen) { i := add(i, 32) } { mstore(add(offset, i), mload(add(e, add(32, i)))) }
            offset := add(offset, elen)
            // mod
            for { let i := 0 } lt(i, mlen) { i := add(i, 32) } { mstore(add(offset, i), mload(add(modn, add(32, i)))) }
            // allocate pointer for return buffer in-place
            ret := add(input, 32)
            // staticcall to precompile 0x05 ------------------------------------------------
            let insize := add(add(96, blen), add(elen, mlen))
            if iszero(staticcall(gas(), MODEXP_PRECOMPILE, ptr, insize, add(base, 32), mlen)) { revert(0, 0) }
            // The precompile overwrote `base` buffer with the result; expose it
            ret := base
        }
    }

    // r = (a + c) mod p   (c is small)
    function _addModConst(bytes memory a, uint256 c) private pure returns (bytes memory r) {
        (uint256 hi, uint256 lo) = _splitWords(a);
        unchecked {
            uint256 nlo = lo + c;
            uint256 nhi = hi + (nlo < c ? 1 : 0);
            r = _joinWords(nhi, nlo);
            // if r ≥ p subtract p
            if (!_lt(nhi, lo, P_HI, P_LO)) {
                (nhi, nlo) = _subWords(nhi, nlo, P_HI, P_LO);
                r = _joinWords(nhi, nlo);
            }
        }
    }

    // r = (a - b) mod p  (assumes a≥b)
    function _subMod(bytes memory a, bytes memory b) private pure returns (bytes memory r) {
        (uint256 ahi, uint256 alo) = _splitWords(a);
        (uint256 bhi, uint256 blo) = _splitWords(b);
        (uint256 nhi, uint256 nlo) = _subWords(ahi, alo, bhi, blo);
        r = _joinWords(nhi, nlo);
    }

    // ---------------- low-level helpers on 512-bit ints ----------------------

    function _splitWords(bytes memory be64) private pure returns (uint256 hi, uint256 lo) {
        assembly {
            hi := mload(add(be64, 32))
            lo := mload(add(be64, 64))
        }
    }

    function _joinWords(uint256 hi, uint256 lo) private pure returns (bytes memory out) {
        out = new bytes(64);
        assembly {
            mstore(add(out, 32), hi)
            mstore(add(out, 64), lo)
        }
    }

    function _subWords(uint256 hiA, uint256 loA, uint256 hiB, uint256 loB)
        private
        pure
        returns (uint256 hi, uint256 lo)
    {
        unchecked {
            if (loA >= loB) {
                lo = loA - loB;
                hi = hiA - hiB;
            } else {
                lo = (type(uint256).max - loB) + loA + 1;
                hi = hiA - hiB - 1;
            }
        }
    }

    function _lt(uint256 hiA, uint256 loA, uint256 hiB, uint256 loB) private pure returns (bool) {
        return (hiA < hiB) || (hiA == hiB && loA < loB);
    }
}
