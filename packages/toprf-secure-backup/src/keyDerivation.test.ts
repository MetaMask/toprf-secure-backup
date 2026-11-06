import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
  deriveEnvelopeKeys,
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

  describe('deriveEnvelopeKeys', () => {
    // Fixed test vector. The controller derives the same keys from the same
    // seed, so changing this output breaks existing envelopes.
    it('should match the fixed test vector for the seed 0x01..0x20', () => {
      const seed = new Uint8Array(32).map((_, i) => i + 1);
      const { authKeyPair, wrapKey } = deriveEnvelopeKeys(seed);

      expect(authKeyPair.sk.toString(16)).toBe(
        '89d3a659522898c5ccb08818a69e8a53c909f19b4afde4b3d71cb7897b341d63',
      );
      expect(bytesToHex(authKeyPair.pk)).toBe(
        '041f53fd295a4e788b08e083a2b593d489a4eb7a78737c0b46fe797d08bbad587a1e41a00a5507cfb8fa267b748632f84ac134213d12f89e95e16b469c31981a2c',
      );
      expect(bytesToHex(wrapKey)).toBe(
        '627fea88261860c6559afcf51f1e21bf7c2135cafa41870c00242ee54d801c10',
      );
    });

    it('should derive a key pair that signs and verifies', () => {
      const { authKeyPair } = deriveEnvelopeKeys(generateRandomSeed());
      const message = new Uint8Array([1, 2, 3]);
      const signature = secp256k1.sign(message, authKeyPair.sk);

      expect(secp256k1.verify(signature, message, authKeyPair.pk)).toBe(true);
    });

    it('should produce different keys from the other seed derivations', () => {
      const seed = generateRandomSeed();
      const { authKeyPair, wrapKey } = deriveEnvelopeKeys(seed);

      expect(authKeyPair.pk).not.toStrictEqual(
        deriveAuthenticationKeyPair(seed).pk,
      );
      expect(wrapKey).not.toStrictEqual(deriveEncryptionKey(seed));
    });
  });
});
