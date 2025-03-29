// Disabling `id-length` because `F(k, x)` is common terminology in the context
// of PRFs.
/* eslint-disable id-length */

import BN from 'bn.js';
import { ec as EC } from 'elliptic';
import { secp256k1 } from 'ethereum-cryptography/secp256k1';

import { deriveAuthenticationKeyPair } from './keyDerivation';
import { lagrangeInterpolationForPoints } from './lagrangeInterpolation';
import { generateRandomScalar, OPRF } from './oprf';
import { generateRandomPolynomial } from '../../auth-network-utils/src/lagrangeInterpolation';

describe('OPRF', () => {
  const testInput = new Uint8Array([1, 2, 3, 4]);
  const testKey = generateRandomScalar();

  const ec = new EC('secp256k1');

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

  it('should recover correct result using threshold OPRF with Lagrange interpolation', () => {
    const threshold = 3;
    const degree = threshold - 1;
    const totalShares = 5;

    // Create a polynomial with testKey as the constant term
    const testKeyBN = new BN(testKey.toString());
    const polynomial = generateRandomPolynomial(ec, degree, testKeyBN);

    // Generate shares from the polynomial
    const shares: { x: bigint; y: bigint }[] = [];
    for (let i = 1; i <= totalShares; i++) {
      const x = BigInt(i);
      const y = BigInt(polynomial.polyEval(new BN(i)).toString());
      shares.push({ x, y });
    }

    // Client blinds input
    const { a: blindedInput, r } = OPRF.blind(testInput);

    // Each server evaluates the blinded input with its key share
    const evaluatedPoints = shares.map((share) => ({
      x: share.x,
      point: OPRF.blindEval(share.y, blindedInput),
    }));

    // Randomly select threshold number of points
    const selectedPoints = evaluatedPoints
      .sort(() => Math.random() - 0.5)
      .slice(0, threshold);
    const nodeIndex = selectedPoints.map((point) => point.x);
    const curvePoints = selectedPoints.map((point) => point.point);

    // Interpolate the curve points directly using Lagrange interpolation
    const reconstructedPoint = lagrangeInterpolationForPoints(
      ec,
      curvePoints,
      nodeIndex,
    );

    // Unblind and hash the result
    const remoteY = OPRF.unblindAndHash(testInput, reconstructedPoint, r);

    // Compare with evaluation using the original key
    const localY = OPRF.localEval(testKey, testInput);
    expect(remoteY).toStrictEqual(localY);

    const keyPair1 = deriveAuthenticationKeyPair(remoteY);
    const keyPair2 = deriveAuthenticationKeyPair(localY);
    expect(keyPair1.pk).toStrictEqual(keyPair2.pk);
  });
});
