// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0;

/**
 * @title The ERC-2771 Recipient Base Abstract Class - Declarations
 *
 * @notice A contract must implement this interface in order to support relayed transaction.
 *
 * @notice It is recommended that your contract inherits from the ERC2771Recipient contract.
 */
abstract contract IERC2771Recipient {

    /**
     * :warning: **Warning** :warning: The Forwarder can have a full control over your Recipient. Only trust verified Forwarder.
     * @param forwarder The address of the Forwarder contract that is being used.
     * @return isTrustedForwarder `true` if the Forwarder is trusted to forward relayed transactions by this Recipient.
     */
    function isTrustedForwarder(address forwarder) public virtual view returns(bool);

    /**
     * @notice Use this method the contract anywhere instead of msg.sender to support relayed transactions.
     * @return sender The real sender of this call.
     * For a call that came through the Forwarder the real sender is extracted from the last 20 bytes of the `msg.data`.
     * Otherwise simply returns `msg.sender`.
     */
    function _msgSender() internal virtual view returns (address);

    /**
     * @notice Use this method in the contract instead of `msg.data` when difference matters (hashing, signature, etc.)
     * @return data The real `msg.data` of this call.
     * For a call that came through the Forwarder, the real sender address was appended as the last 20 bytes
     * of the `msg.data` - so this method will strip those 20 bytes off.
     * Otherwise (if the call was made directly and not through the forwarder) simply returns `msg.data`.
     */
    function _msgData() internal virtual view returns (bytes calldata);
}

// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)



/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)




// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)



/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Down, // Toward negative infinity
        Up, // Toward infinity
        Zero // Toward zero
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds up instead
     * of rounding down.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)
     * with further edits by Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division.
            if (prod1 == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return prod0 / denominator;
            }

            // Make sure the result is less than 2^256. Also prevents denominator == 0.
            require(denominator > prod1, "Math: mulDiv overflow");

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            uint256 remainder;
            assembly {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.
            // See https://cs.stackexchange.com/q/138556/92363.

            // Does not overflow because the denominator cannot be zero at this stage in the function.
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such
            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv = 1 mod 2^4.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works
            // in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2^8
            inverse *= 2 - denominator * inverse; // inverse mod 2^16
            inverse *= 2 - denominator * inverse; // inverse mod 2^32
            inverse *= 2 - denominator * inverse; // inverse mod 2^64
            inverse *= 2 - denominator * inverse; // inverse mod 2^128
            inverse *= 2 - denominator * inverse; // inverse mod 2^256

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is
            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inverse;
            return result;
        }
    }

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.
     *
     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.
        //
        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have
        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.
        //
        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`
        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`
        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`
        //
        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.
        uint256 result = 1 << (log2(a) >> 1);

        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,
        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at
        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision
        // into the expected uint128 result.
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }

    /**
     * @notice Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256, rounded down, of a positive value.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);
        }
    }
}


// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)



/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // must be unchecked in order to support `n = type(int256).min`
            return uint256(n >= 0 ? n : -n);
        }
    }
}


/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            /// @solidity memory-safe-assembly
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toString(int256 value) internal pure returns (string memory) {
        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}




// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)





/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV // Deprecated in v4.8
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, hash)
            message := keccak256(0x00, 0x3c)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from `s`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 data) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            data := keccak256(ptr, 0x42)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Data with intended validator, created from a
     * `validator` and `data` according to the version 0 of EIP-191.
     *
     * See {recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x00", validator, data));
    }
}


// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)



/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}


// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/IERC721.sol)





/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721
     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must
     * understand this adds an external call which potentially creates a reentrancy vulnerability.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}


// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC721/IERC721Receiver.sol)



/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}


// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC1155/IERC1155.sol)





/**
 * @dev Required interface of an ERC1155 compliant contract, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1155[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155 is IERC165 {
    /**
     * @dev Emitted when `value` tokens of token type `id` are transferred from `from` to `to` by `operator`.
     */
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    /**
     * @dev Equivalent to multiple {TransferSingle} events, where `operator`, `from` and `to` are the same for all
     * transfers.
     */
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );

    /**
     * @dev Emitted when `account` grants or revokes permission to `operator` to transfer their tokens, according to
     * `approved`.
     */
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    /**
     * @dev Emitted when the URI for token type `id` changes to `value`, if it is a non-programmatic URI.
     *
     * If an {URI} event was emitted for `id`, the standard
     * https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[guarantees] that `value` will equal the value
     * returned by {IERC1155MetadataURI-uri}.
     */
    event URI(string value, uint256 indexed id);

    /**
     * @dev Returns the amount of tokens of token type `id` owned by `account`.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    ) external view returns (uint256[] memory);

    /**
     * @dev Grants or revokes permission to `operator` to transfer the caller's tokens, according to `approved`,
     *
     * Emits an {ApprovalForAll} event.
     *
     * Requirements:
     *
     * - `operator` cannot be the caller.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns true if `operator` is approved to transfer ``account``'s tokens.
     *
     * See {setApprovalForAll}.
     */
    function isApprovedForAll(address account, address operator) external view returns (bool);

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If the caller is not `from`, it must have been approved to spend ``from``'s tokens via {setApprovalForAll}.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}


// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/IERC1155Receiver.sol)





/**
 * @dev _Available since v3.1._
 */
interface IERC1155Receiver is IERC165 {
    /**
     * @dev Handles the receipt of a single ERC1155 token type. This function is
     * called at the end of a `safeTransferFrom` after the balance has been updated.
     *
     * NOTE: To accept the transfer, this must return
     * `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
     * (i.e. 0xf23a6e61, or its own function selector).
     *
     * @param operator The address which initiated the transfer (i.e. msg.sender)
     * @param from The address which previously owned the token
     * @param id The ID of the token being transferred
     * @param value The amount of tokens being transferred
     * @param data Additional data with no specified format
     * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed
     */
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);

    /**
     * @dev Handles the receipt of a multiple ERC1155 token types. This function
     * is called at the end of a `safeBatchTransferFrom` after the balances have
     * been updated.
     *
     * NOTE: To accept the transfer(s), this must return
     * `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
     * (i.e. 0xbc197c81, or its own function selector).
     *
     * @param operator The address which initiated the batch transfer (i.e. msg.sender)
     * @param from The address which previously owned the token
     * @param ids An array containing ids of each token being transferred (order and length must match values array)
     * @param values An array containing amounts of each token being transferred (order and length must match ids array)
     * @param data Additional data with no specified format
     * @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if transfer is allowed
     */
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}


// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)




// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)



/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}


/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}


// solhint-disable no-inline-assembly




/**
 * @title The ERC-2771 Recipient Base Abstract Class - Implementation
 *
 * @notice Note that this contract was called `BaseRelayRecipient` in the previous revision of the GSN.
 *
 * @notice A base contract to be inherited by any contract that want to receive relayed transactions.
 *
 * @notice A subclass must use `_msgSender()` instead of `msg.sender`.
 */
abstract contract ERC2771Recipient is IERC2771Recipient {

    /*
     * Forwarder singleton we accept calls from
     */
    address private _trustedForwarder;

    /**
     * :warning: **Warning** :warning: The Forwarder can have a full control over your Recipient. Only trust verified Forwarder.
     * @notice Method is not a required method to allow Recipients to trust multiple Forwarders. Not recommended yet.
     * @return forwarder The address of the Forwarder contract that is being used.
     */
    function getTrustedForwarder() public virtual view returns (address forwarder){
        return _trustedForwarder;
    }

    function _setTrustedForwarder(address _forwarder) internal {
        _trustedForwarder = _forwarder;
    }

    /// @inheritdoc IERC2771Recipient
    function isTrustedForwarder(address forwarder) public virtual override view returns(bool) {
        return forwarder == _trustedForwarder;
    }

    /// @inheritdoc IERC2771Recipient
    function _msgSender() internal override virtual view returns (address ret) {
        if (msg.data.length >= 20 && isTrustedForwarder(msg.sender)) {
            // At this point we know that the sender is a trusted forwarder,
            // so we trust that the last bytes of msg.data are the verified sender address.
            // extract sender address from the end of msg.data
            assembly {
                ret := shr(96,calldataload(sub(calldatasize(),20)))
            }
        } else {
            ret = msg.sender;
        }
    }

    /// @inheritdoc IERC2771Recipient
    function _msgData() internal override virtual view returns (bytes calldata ret) {
        if (msg.data.length >= 20 && isTrustedForwarder(msg.sender)) {
            return msg.data[0:msg.data.length-20];
        } else {
            return msg.data;
        }
    }
}





contract Frens is IERC721Receiver, IERC1155Receiver, ERC2771Recipient, Ownable {
    enum TokenType{ Native, ERC20, ERC721, ERC1155 }
    uint256 public lockBlocks = 100; 
    address[] public whiteListTokens;
    
    mapping(TokenType => uint256) public gasLimitConfigs;
    uint256 public baseGasFee = 0;
    uint256 public priorityGasFee = 0;
    uint256 public constant minGasLimit = 21000;

    uint256 public constant defaultProtocolFee = 0.0005 ether;
    mapping(TokenType => uint256) public protocolFeeConfigs;
    uint256 public protocolBalance = 0;

    struct Deposit {
        uint256     tokenAmount; // Amount of the token
        address     tokenAddress; // Address of the token. 0x0 for ETH
        TokenType   tokenType;  // TokenType following by the enumations
        uint256     tokenId; // ID of the token if erc721 or erc1155
        address     pubKey; // Key to lock the token
        address     sender; // Address of the sender
        uint256     blockNo; // The block of deposit
    }

    Deposit[] public deposits;

    event DepositEvent(uint256 _index, uint8 _tokenType, address _tokenAddress, uint256 _tokenAmount, address indexed _sender);
    event ClaimEvent(uint256 _index, uint8 _tokenType, address _tokenAddress, uint256 _tokenAmount, address indexed _recipient);
    event WithdrawEvent(address indexed _payee, uint256 _amount);

    constructor(address forwarder) {
        _setTrustedForwarder(forwarder);
        baseGasFee = 40 gwei;
        priorityGasFee = 0;
        gasLimitConfigs[TokenType.Native] = minGasLimit;
        gasLimitConfigs[TokenType.ERC20] = 65000;
        gasLimitConfigs[TokenType.ERC721] = 300000;
        gasLimitConfigs[TokenType.ERC1155] = 300000;
    }

    function getGasPrice() public view returns (uint256) {
        uint256 gasPrice;
        assembly {
            gasPrice := gasprice()
        }
        return gasPrice;
    }

    function setTrustedForwarder(address _forwarder) external onlyOwner {
        _setTrustedForwarder(_forwarder);
    }

    function setLockBlocks(uint256 _lockBlocks) external onlyOwner {
        lockBlocks = _lockBlocks;
    }

    function setWhiteListTokens(address[] memory _tokenAddress) external  onlyOwner {
        whiteListTokens = _tokenAddress;
    }

    function isAllowDepositToken(address _tokenAddress) public view returns(bool){
        if (whiteListTokens.length == 0) {
            return true;
        }
        for (uint256 i = 0; i< whiteListTokens.length; i++) {
            if (whiteListTokens[i] == _tokenAddress) {
                return true;
            }
        }
        return false;
    }

    function setGasLimit(TokenType _tokenType, uint256 _gasLimit) external onlyOwner {
        require(uint8(_tokenType) < 4, "INVALID CONTRACT TYPE");
        require(_gasLimit >= minGasLimit, "INVALID GAS LIMIT");
        gasLimitConfigs[_tokenType] = _gasLimit;
    }

    function setBaseGasFee(uint256 _baseGasFee) external onlyOwner {
        baseGasFee = _baseGasFee;
    }

    function setPriorityGasFee(uint256 _priorityGasFee) external onlyOwner {
        priorityGasFee = _priorityGasFee;
    }

    function setProtocolFee(TokenType _tokenType, uint256 _protocolFee) external onlyOwner {
        require(uint8(_tokenType) < 4, "INVALID CONTRACT TYPE");
        require(_protocolFee > 0, "INVALID PROCOL FEE");
        protocolFeeConfigs[_tokenType] = _protocolFee;
    }

    function estimateGasFeeForClaim(TokenType _tokenType) public view returns(uint256) {
        uint256 gasLimit = gasLimitConfigs[_tokenType];
        if (gasLimit == 0) {
            gasLimit = minGasLimit;
        }
        uint256 gasPrice = baseGasFee + priorityGasFee;
        return gasLimit * gasPrice;
    }

    function estimateProtocolFee(TokenType _tokenType) public view returns(uint256) {
        uint256 fee = protocolFeeConfigs[_tokenType];
        if (fee == 0) {
            return defaultProtocolFee;
        }
        return fee;
    }

    function estimateDepositFee(TokenType _tokenType) public view returns(uint256) {
        return estimateProtocolFee(_tokenType) + estimateGasFeeForClaim(_tokenType);
    }

    function makeDeposit(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        uint256 _tokenId,
        address _pubKey
    ) external payable returns (uint256) {
        require(uint8(_tokenType) < 4, "INVALID CONTRACT TYPE");
        require(isAllowDepositToken(_tokenAddress), "TokenAddress is not allowed");
        uint256 _depositFee = estimateDepositFee(_tokenType);
        require(msg.value >= _depositFee, "NOT ENOUGH PROTOCOL FEE");

        if (_tokenType == TokenType.Native) {
            _tokenAmount = msg.value - _depositFee;
            require(_tokenAddress == address(0), "tokenAddress must be zero");
            protocolBalance += _depositFee;
        } else {
            require(_tokenAddress != address(0), "tokenAddress must not be zero");
            protocolBalance += msg.value;
        }

        require(_tokenAmount > 0, "YOU CAN NOT SEND ZERO TOKEN");
        processDeposit(_tokenType, _tokenAddress, _tokenAmount, _tokenId);
        return insertDeposit(_tokenType, _tokenAddress, _tokenAmount, _tokenId, _pubKey);
    }

    function processDeposit(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        uint256 _tokenId
        ) private {
        if (_tokenType == TokenType.ERC20) {
            IERC20 token = IERC20(_tokenAddress);
            require(
                token.balanceOf(_msgSender()) >= _tokenAmount,
                "INSUFFICIENT TOKEN BALANCE"
            );
            require(
                token.allowance(_msgSender(), address(this)) >= _tokenAmount,
                "INSUFFICIENT ALLOWANCE"
            );
            require(
                token.transferFrom(_msgSender(), address(this), _tokenAmount),
                "TRANSFER FAILED. CHECK ALLOWANCE & BALANCE"
            );
        } else if (_tokenType == TokenType.ERC721) {
            _tokenAmount = 1;
            IERC721 token = IERC721(_tokenAddress);
            token.safeTransferFrom(
                _msgSender(),
                address(this),
                _tokenId,
                "Internal transfer"
            );
        } else if (_tokenType == TokenType.ERC1155) {
            IERC1155 token = IERC1155(_tokenAddress);
            token.safeTransferFrom(
                _msgSender(),
                address(this),
                _tokenId,
                _tokenAmount,
                "Internal transfer"
            );
        }
    }

    function insertDeposit(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        uint256 _tokenId,
        address _pubKey
    ) private returns (uint256) {
        // add deposit
        deposits.push(
            Deposit({
                tokenType: _tokenType,
                tokenAddress: _tokenAddress,
                tokenAmount: _tokenAmount,
                tokenId: _tokenId,
                pubKey: _pubKey,
                sender: _msgSender(),
                blockNo: block.number
            })
        );
        // emit the deposit event
        emit DepositEvent(
            deposits.length - 1, 
            uint8(_tokenType),
            _tokenAddress,
            _tokenAmount,
            _msgSender()
        );
        return deposits.length - 1;
    }

    function makeBatchDeposits(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        address[] memory _pubKeys
    ) external payable returns (uint256[] memory) {
        require(_pubKeys.length > 0, "pubKeys can not be empty");
        require(uint8(_tokenType) < 2, "INVALID CONTRACT TYPE");
        require(isAllowDepositToken(_tokenAddress), "TokenAddress is not allowed");

        uint256 _depositFee = _pubKeys.length * estimateDepositFee(_tokenType);
        require(msg.value >= _depositFee, "NOT ENOUGH PROTOCOL FEE");

        if (_tokenType == TokenType.Native) {
            _tokenAmount = msg.value - _depositFee;
            require(_tokenAddress == address(0), "tokenAddress must be zero");
            protocolBalance += _depositFee;
        } else {
            require(_tokenAddress != address(0), "tokenAddress must not be zero");
            protocolBalance += msg.value;
        }

        require(_tokenAmount > 0, "YOU CAN NOT SEND ZERO TOKEN");
        processDeposit(_tokenType, _tokenAddress, _tokenAmount, 0);

        uint256 amountPerDeposit = _tokenAmount/_pubKeys.length;
        uint256[] memory depositIndexes = new uint256[](_pubKeys.length);
        for (uint256 i = 0; i< _pubKeys.length; i++) {
            depositIndexes[i] = insertDeposit(_tokenType, _tokenAddress, amountPerDeposit, 0, _pubKeys[i]);
        }
        return depositIndexes;
    }

    /**
     * @notice Erc721 token receiver function
     * @dev These functions are called by the token contracts when a token is sent to this contract
     * @dev If calldata is "Internal transfer" then the token was sent by this contract and we don't need to do anything
     * @dev Otherwise, calldata needs a 20 byte pubkey
     * @param _operator address operator requesting the transfer
     * @param _from address address which previously owned the token
     * @param _tokenId uint256 ID of the token being transferred
     * @param _data bytes data to send along with a safe transfer check
     */
    function onERC721Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        bytes calldata _data
    ) external pure override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            return this.onERC721Received.selector;
        } else {
            revert("NOT ALLOW RECEIVING ERC721");
        }
    }

    /**
        @notice Erc1155 token receiver function
        @dev These functions are called by the token contracts when a token is sent to this contract
        @dev If calldata is "Internal transfer" then the token was sent by this contract and we don't need to do anything
        @dev Otherwise, calldata needs 20 bytes pubKey
        @param _operator address operator requesting the transfer
        @param _from address address which previously owned the token
        @param _tokenId uint256 ID of the token being transferred
        @param _value uint256 amount of tokens being transferred
        @param _data bytes data passed with the call
     */
    function onERC1155Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        uint256 _value,
        bytes calldata _data
    ) external pure override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC1155Received.selector;
        } else {
            revert("NOT ALLOW RECEIVING ERC721");
        }
    }

    /**
     * @notice Erc1155 token receiver function
     * @dev These functions are called by the token contracts when a set of tokens is sent to this contract
     * @dev If calldata is "Internal transfer" then the token was sent by this contract and we don't need to do anything
     * @param _operator address operator requesting the transfer
     * @param _from address address which previously owned the token
     * @param _ids uint256[] IDs of each token being transferred (order and length must match _values array)
     * @param _values uint256[] amount of each token being transferred (order and length must match _ids array)
     * @param _data bytes data forwarded from the caller
     * @dev _data needs to contain array of 20 byte pubKeys (length must match _ids and _values arrays)
     */
    function onERC1155BatchReceived(
        address _operator,
        address _from,
        uint256[] calldata _ids,
        uint256[] calldata _values,
        bytes calldata _data
    ) external pure override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC1155BatchReceived.selector;
        } else {
            revert("NOT ALLOW RECEIVING ERC721");
        }
    }

    /**
     * @notice Function to claim a deposit. Withdraws the deposit to the recipient address.
     * @dev _recipientAddressHash is hash("\x19Ethereum Signed Message:\n32" + hash(_recipientAddress))
     * @dev The signature should be signed with the private key corresponding to the public key stored in the deposit
     * @dev We don't check the unhashed address for security reasons. It's preferable to sign a hash of the address.
     * @param _index uint256 index of the deposit
     * @param _recipientAddress address of the recipient
     * @param _recipientAddressHash bytes32 hash of the recipient address (prefixed with "\x19Ethereum Signed Message:\n32")
     * @param _signature bytes signature of the recipient address (65 bytes)
     * @return bool true if successful
     */
    function claimDeposit(
        uint256 _index,
        address _recipientAddress,
        bytes32 _recipientAddressHash,
        bytes memory _signature
    ) external returns (bool) {
        // check that the deposit exists and that it isn't already withdrawn
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        Deposit memory _deposit = deposits[_index];
        require(_deposit.tokenAmount > 0, "DEPOSIT ALREADY WITHDRAWN");
        // check that the recipientAddress hashes to the same value as recipientAddressHash
        require(
            _recipientAddressHash ==
                ECDSA.toEthSignedMessageHash(
                    keccak256(abi.encodePacked(_recipientAddress))
                ),
            "HASHES DO NOT MATCH"
        );
        // check that the signer is the same as the one stored in the deposit
        address depositSigner = getSigner(_recipientAddressHash, _signature);
        require(depositSigner == _deposit.pubKey, "WRONG SIGNATURE");

        // Deposit request is valid. Withdraw the deposit to the recipient address.
        if (_deposit.tokenType == TokenType.Native) {
            /// handle eth deposits
            payable(_recipientAddress).transfer(_deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC20) {
            // handle erc20 deposits
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.transfer(_recipientAddress, _deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC721) {
            // handle erc721 deposits
            IERC721 token = IERC721(_deposit.tokenAddress);
            token.transferFrom(
                address(this),
                _recipientAddress,
                _deposit.tokenId
            );
        } else if (_deposit.tokenType == TokenType.ERC1155) {
            // handle erc1155 deposits
            IERC1155 token = IERC1155(_deposit.tokenAddress);
            token.safeTransferFrom(
                address(this),
                _recipientAddress,
                _deposit.tokenId,
                _deposit.tokenAmount,
                ""
            );
        }

        // emit the withdraw event
        emit ClaimEvent(
            _index,
            uint8(_deposit.tokenType),
            _deposit.tokenAddress,
            _deposit.tokenAmount,
            _recipientAddress
        );

        // delete the deposit
        delete deposits[_index];

        return true;
    }

    // sender can withdraw deposited assets after some blocks
    function claimBySender(uint256 _index) external {
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        Deposit memory _deposit = deposits[_index];
        require(
            block.number >= _deposit.blockNo + lockBlocks ,
            "SENDER MUST WAIT AFTER SOME BLOCKS TO WITHDRAW"
        );
        require(
            _deposit.sender == _msgSender(),
            "MUST BE SENDER TO WITHDRAW"
        );

        // handle eth deposits
        if (_deposit.tokenType == TokenType.Native) {
            // send eth to sender
            payable(_msgSender()).transfer(_deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC20) {
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.transfer(_msgSender(), _deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC721) {
            IERC721 token = IERC721(_deposit.tokenAddress);
            token.transferFrom(
                address(this),
                _msgSender(),
                _deposit.tokenId
            );
        } else if (_deposit.tokenType == TokenType.ERC1155) {
            IERC1155 token = IERC1155(_deposit.tokenAddress);
            token.safeTransferFrom(
                address(this),
                _msgSender(),
                _deposit.tokenId,
                _deposit.tokenAmount,
                ""
            );
        }

        // emit the withdraw event
        emit ClaimEvent(
            _index,
            uint8(_deposit.tokenType),
            _deposit.tokenAddress,
            _deposit.tokenAmount,
            _msgSender()
        );

        // delete the deposit
        delete deposits[_index];
    }


    function withdrawProfit(address payable payee) external onlyOwner {
        require(protocolBalance > 0, "No profit");
        payee.transfer(protocolBalance);
        emit WithdrawEvent(payee, protocolBalance);
        protocolBalance = 0;
    }

    /**
     * @notice Gets the signer of a messageHash. Used for signature verification.
     * @dev Uses ECDSA.recover. On Frontend, use secp256k1 to sign the messageHash
     * @dev also remember to prepend the messageHash with "\x19Ethereum Signed Message:\n32"
     * @param messageHash bytes32 hash of the message
     * @param signature bytes signature of the message
     * @return address of the signer
     */
    function getSigner(bytes32 messageHash, bytes memory signature)
        internal
        pure
        returns (address)
    {
        address signer = ECDSA.recover(messageHash, signature);
        return signer;
    }

    /**
     * @notice Simple way to get the total number of deposits
     * @return uint256 number of deposits
     */
    function getDepositCount() external view returns (uint256) {
        return deposits.length;
    }

    /**
        @notice supportsInterface function
        @dev ERC165 interface detection
        @param _interfaceId bytes4 the interface identifier, as specified in ERC-165
        @return bool true if the contract implements the interface specified in _interfaceId
     */
    function supportsInterface(bytes4 _interfaceId)
        external
        pure
        override
        returns (bool)
    {
        return
            _interfaceId == type(IERC165).interfaceId ||
            _interfaceId == type(IERC721Receiver).interfaceId ||
            _interfaceId == type(IERC1155Receiver).interfaceId || 
            _interfaceId == type(IERC2771Recipient).interfaceId;
    }

    function _msgSender() internal view override(Context, ERC2771Recipient)
        returns (address sender) {
        sender = ERC2771Recipient._msgSender();
    }

    function _msgData() internal view override(Context, ERC2771Recipient)
        returns (bytes calldata) {
        return ERC2771Recipient._msgData();
    }

    function getDepositsByAddress(address _address) external view returns (Deposit[] memory) {
        Deposit[] memory _deposits = new Deposit[](deposits.length);
        uint256 count = 0;
        for (uint256 i = 0; i < deposits.length; i++) {
            if (deposits[i].sender == _address) {
                _deposits[count] = deposits[i];
                count++;
            }
        }
        return _deposits;
    }
}



