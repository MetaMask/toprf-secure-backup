// Disabling `id-length` because `F(k, x)` is common terminology in the context
// of PRFs.
/* eslint-disable id-length */

import { secp256k1 } from 'ethereum-cryptography/secp256k1';
import { generateRandomScalar, OPRF } from './oprf';

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

  it('should unblind and hash correctly', () => {
    const { a, r } = OPRF.blind(testInput);
    const k = testKey;
    const b = OPRF.blindEval(k, a);
    const y = OPRF.unblindAndHash(testInput, b, r);
    expect(y).toBeInstanceOf(Uint8Array);
    expect(y.length).toBeGreaterThan(0);
  });

  it('should perform local evaluation correctly', () => {
    const k = generateRandomScalar();
    const y = OPRF.localEval(k, testInput);
    expect(y).toBeInstanceOf(Uint8Array);
    expect(y.length).toBeGreaterThan(0);
  });

  it('should produce consistent results for the same input and key', () => {
    const k = generateRandomScalar();
    const y1 = OPRF.localEval(k, testInput);
    const y2 = OPRF.localEval(k, testInput);
    expect(y1).toStrictEqual(y2);
  });

  it('should produce different results for different inputs', () => {
    const k = generateRandomScalar();
    const y1 = OPRF.localEval(k, testInput);
    const y2 = OPRF.localEval(k, new Uint8Array([5, 6, 7, 8]));
    expect(y1).not.toStrictEqual(y2);
  });

  it('should produce consistent results for local and remote evaluation', () => {
    const k = generateRandomScalar();
    const { a, r } = OPRF.blind(testInput);
    const b = OPRF.blindEval(k, a);
    const yRemote = OPRF.unblindAndHash(testInput, b, r);
    const yLocal = OPRF.localEval(k, testInput);
    expect(yRemote).toStrictEqual(yLocal);
  });

  it('should perform remote evaluation correctly with secret-shared key', () => {
    const k1 = generateRandomScalar();
    const k2 = generateRandomScalar();
    const { a, r } = OPRF.blind(testInput);
    const b1 = OPRF.blindEval(k1, a);
    const b2 = OPRF.blindEval(k2, a);
    const b = b1.add(b2);
    const yRemote = OPRF.unblindAndHash(testInput, b, r);
    const k = (k1 + k2) % secp256k1.CURVE.n;
    const yLocal = OPRF.localEval(k, testInput);
    expect(yRemote).toStrictEqual(yLocal);
  });
});
