"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveEncryptionKey = exports.deriveAuthenticationKeyPair = void 0;
const utils_1 = require("@noble/curves/abstract/utils");
const secp256k1_1 = require("@noble/curves/secp256k1");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha2_1 = require("@noble/hashes/sha2");
const HKDF_AUTHENTICATION_KEY_INFO = 'authentication-key';
const HKDF_ENCRYPTION_KEY_INFO = 'encryption-key';
/**
 * Deterministically derives an secp256k1 keypair intended for authentication.
 *
 * @param seed The input seed from which the output key is derived from.
 * @returns The derived keypair.
 */
function deriveAuthenticationKeyPair(seed) {
    const info = HKDF_AUTHENTICATION_KEY_INFO;
    const k = (0, hkdf_1.hkdf)(sha2_1.sha256, seed, undefined, info, 32); // Derive 256 bit key.
    // Converting from bytes to scalar like this is OK because statistical
    // distance between U(2^256) % secp256k1.n and U(secp256k1.n) is negligible.
    const sk = (0, utils_1.bytesToNumberBE)(k) % secp256k1_1.secp256k1.CURVE.n;
    const pk = secp256k1_1.secp256k1.getPublicKey(sk, false);
    return { sk, pk };
}
exports.deriveAuthenticationKeyPair = deriveAuthenticationKeyPair;
/**
 * Deterministically derives an AES-256 key intended for data encryption.
 *
 * @param seed The input seed from which the output key is derived from.
 * @returns The derived key.
 */
function deriveEncryptionKey(seed) {
    const info = HKDF_ENCRYPTION_KEY_INFO;
    const k = (0, hkdf_1.hkdf)(sha2_1.sha256, seed, undefined, info, 32); // Derive 256 bit key.
    return k;
}
exports.deriveEncryptionKey = deriveEncryptionKey;
//# sourceMappingURL=keyDerivation.cjs.map