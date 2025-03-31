import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

const HKDF_AUTHENTICATION_KEY_INFO = 'authentication-key';
const HKDF_ENCRYPTION_KEY_INFO = 'encryption-key';

/**
 * Deterministically derives an secp256k1 keypair intended for authentication.
 *
 * @param seed The input seed from which the output key is derived from.
 * @returns The derived keypair.
 */
export function deriveAuthenticationKeyPair(seed: Uint8Array): {
  sk: bigint;
  pk: Uint8Array;
} {
  const info = HKDF_AUTHENTICATION_KEY_INFO;
  const k = hkdf(sha256, seed, undefined, info, 32); // Derive 256 bit key.

  // Converting from bytes to scalar like this is OK because statistical
  // distance between U(2^256) % secp256k1.n and U(secp256k1.n) is negligible.
  const sk = bytesToNumberBE(k) % secp256k1.CURVE.n;
  const pk = secp256k1.getPublicKey(sk, false);
  return { sk, pk };
}

/**
 * Deterministically derives an AES-256 key intended for data encryption.
 *
 * @param seed The input seed from which the output key is derived from.
 * @returns The derived key.
 */
export function deriveEncryptionKey(seed: Uint8Array): Uint8Array {
  const info = HKDF_ENCRYPTION_KEY_INFO;
  const k = hkdf(sha256, seed, undefined, info, 32); // Derive 256 bit key.
  return k;
}
