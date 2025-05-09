// Disabling `id-length` because `F(k, x)` is common terminology in the context
// of PRFs.
/* eslint-disable id-length */

import { secp256k1 } from '@noble/curves/secp256k1';
import { pbkdf2Async } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha2';

import { generateRandomScalar, OPRF } from './oprf';

const keyDeriver = {
  // Disable eslint-plugin-jsdoc because this is a test file.
  // eslint-disable-next-line jsdoc/require-jsdoc
  deriveKey: async (
    seed: Uint8Array,
    salt: Uint8Array,
  ): Promise<Uint8Array> => {
    return pbkdf2Async(sha256, seed, salt, {
      dkLen: 32,
      c: 500_000,
    });
  },
};

describe('OPRF', () => {
  const testInput = new Uint8Array([1, 2, 3, 4]);
  const testKey = generateRandomScalar();

  it('should blind input correctly', () => {
    const { a, r } = OPRF.blind(testInput);
    expect(a).toBeDefined();
    expect(r).toBeDefined();
    expect(typeof r).toBe('bigint');
  });

  it('should evaluate blinded input correctly', () => {
    const { a } = OPRF.blind(testInput);
    const k = generateRandomScalar();
    const b = OPRF.blindEval(k, a);
    expect(b).toBeDefined();
  });

  it('should unblind and hash correctly', async () => {
    const { a, r } = OPRF.blind(testInput);
    const k = testKey;
    const b = OPRF.blindEval(k, a);
    const y = await OPRF.unblindAndHash(testInput, b, r);
    expect(y).toBeInstanceOf(Uint8Array);
    expect(y.length).toBeGreaterThan(0);
  });

  it('should perform local evaluation correctly', async () => {
    const k = generateRandomScalar();
    const y = await OPRF.localEval(k, testInput);
    expect(y).toBeInstanceOf(Uint8Array);
    expect(y.length).toBeGreaterThan(0);
  });

  it('should produce consistent results for the same input and key', async () => {
    const k = generateRandomScalar();
    const y1 = await OPRF.localEval(k, testInput);
    const y2 = await OPRF.localEval(k, testInput);
    expect(y1).toStrictEqual(y2);
  });

  it('should produce different results for different inputs', async () => {
    const k = generateRandomScalar();
    const y1 = await OPRF.localEval(k, testInput);
    const y2 = await OPRF.localEval(k, new Uint8Array([5, 6, 7, 8]));
    expect(y1).not.toStrictEqual(y2);
  });

  it('should produce consistent results for local and remote evaluation', async () => {
    const k = generateRandomScalar();
    const { a, r } = OPRF.blind(testInput);
    const b = OPRF.blindEval(k, a);
    const yRemote = await OPRF.unblindAndHash(testInput, b, r);
    const yLocal = await OPRF.localEval(k, testInput);
    expect(yRemote).toStrictEqual(yLocal);
  });

  it('should perform remote evaluation correctly with secret-shared key', async () => {
    const k1 = generateRandomScalar();
    const k2 = generateRandomScalar();
    const { a, r } = OPRF.blind(testInput);
    const b1 = OPRF.blindEval(k1, a);
    const b2 = OPRF.blindEval(k2, a);
    const b = b1.add(b2);
    const yRemote = await OPRF.unblindAndHash(testInput, b, r);
    const k = (k1 + k2) % secp256k1.CURVE.n;
    const yLocal = await OPRF.localEval(k, testInput);
    expect(yRemote).toStrictEqual(yLocal);
  });

  it('should perform remote evaluation correctly with key deriver', async () => {
    const k = generateRandomScalar();
    const { a, r } = OPRF.blind(testInput);
    const b = OPRF.blindEval(k, a);
    const yRemote = await OPRF.unblindAndHash(testInput, b, r, keyDeriver);
    const yLocal = await OPRF.localEval(k, testInput, keyDeriver);
    expect(yRemote).toStrictEqual(yLocal);
  });
});
