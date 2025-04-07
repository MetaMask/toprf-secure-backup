import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from '@noble/hashes/utils';

import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';

/**
 * Generates a random seed of 32 bytes.
 *
 * @returns A random seed of 32 bytes.
 */
function generateRandomSeed(): Uint8Array {
  return randomBytes(32);
}

describe('keyDerivation', () => {
  describe('deriveAuthenticationKeyPair', () => {
    it('should derive a valid secp256k1 keypair from a given seed', () => {
      const seed = generateRandomSeed();
      const { sk, pk } = deriveAuthenticationKeyPair(seed);

      expect(sk).toBeDefined();
      expect(pk).toBeDefined();

      // Attempt to sign and verify a message.
      const message = new Uint8Array([1, 2, 3]);
      const signature = secp256k1.sign(message, sk);
      const isValid = secp256k1.verify(signature, message, pk);
      expect(isValid).toBe(true);
    });

    it('should produce deterministic results for the same seed', () => {
      const seed = generateRandomSeed();
      const keyPair1 = deriveAuthenticationKeyPair(seed);
      const keyPair2 = deriveAuthenticationKeyPair(seed);

      expect(keyPair1).toStrictEqual(keyPair2);
    });

    it('should produce different results for different seeds', () => {
      const seed1 = generateRandomSeed();
      const seed2 = generateRandomSeed();

      const keyPair1 = deriveAuthenticationKeyPair(seed1);
      const keyPair2 = deriveAuthenticationKeyPair(seed2);

      expect(keyPair1).not.toStrictEqual(keyPair2);
    });
  });

  describe('deriveEncryptionKey', () => {
    it('should derive a valid AES-256 key from a given seed', () => {
      const seed = generateRandomSeed();
      const key = deriveEncryptionKey(seed);

      expect(key).toBeDefined();
      expect(key).toHaveLength(32); // AES-256 key length
    });

    it('should produce deterministic results for the same seed', () => {
      const seed = generateRandomSeed();
      const key1 = deriveEncryptionKey(seed);
      const key2 = deriveEncryptionKey(seed);

      expect(key1).toStrictEqual(key2);
    });

    it('should produce different results for different seeds', () => {
      const seed1 = generateRandomSeed();
      const seed2 = generateRandomSeed();

      const key1 = deriveEncryptionKey(seed1);
      const key2 = deriveEncryptionKey(seed2);

      expect(key1).not.toStrictEqual(key2);
    });
  });
});
