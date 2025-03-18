import { KEY_TYPE } from '@toruslabs/constants';
import BN from 'bn.js';

import { getKeyCurve } from './keys';
import {
  generateRandomPolynomial,
  lagrangeInterpolatePolynomial,
  lagrangeInterpolation,
} from './lagrangeInterpolation';
import Point from './point';

describe('lagrange interpolation', function () {
  it('should generate random polynomial', function () {
    const degree = 5;
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);

    const result = generateRandomPolynomial(curve, degree);
    // number of polynomials should be equal to the degree + 1 (inital secret)
    expect(result.polynomial).toHaveLength(degree + 1);
  });

  it('should generate random polynomial with secret', function () {
    const degree = 5;
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);
    const secret = new BN(100);

    const result = generateRandomPolynomial(curve, degree, secret);

    const firstPolynomial = result.polynomial[0];
    // if secret is provided, the first polynomial should be equal to the secret
    expect(firstPolynomial.eq(secret)).toBe(true);
  });

  it('should reconstruct secret from shares using lagrangeInterpolation', function () {
    const degree = 5;
    const sharesRequired = degree + 1;
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);
    const secret = new BN(1234567890);

    const polynomial = generateRandomPolynomial(curve, degree, secret);

    const shareIndexes = Array.from(
      { length: sharesRequired },
      (_, i) => new BN(i),
    );
    const shareMap = polynomial.generateShares(shareIndexes);

    const shares = Object.values(shareMap).map(({ share }) => share);
    const reconstructedSecret = lagrangeInterpolation(
      curve,
      shares,
      shareIndexes,
    );

    expect(reconstructedSecret.eq(secret)).toBe(true);
  });

  it('should reconstruct secret from shares using lagrangeInterpolatePolynomial', function () {
    const degree = 5;
    const sharesRequired = degree + 1;
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);
    const secret = new BN(1234567890);

    const polynomial = generateRandomPolynomial(curve, degree, secret);

    const shareIndexes = Array.from(
      { length: sharesRequired },
      (_, i) => new BN(i),
    );
    const shareMap = polynomial.generateShares(shareIndexes);

    const points = Object.values(shareMap).map(
      ({ share, shareIndex }) => new Point(shareIndex, share, curve),
    );
    const reconstructedPolynomial = lagrangeInterpolatePolynomial(
      curve,
      points,
    );
    const reconstructedSecret = reconstructedPolynomial.polynomial[0];

    expect(reconstructedSecret.eq(secret)).toBe(true);
  });

  it('should correctly interpolate polynomial through all points', function () {
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);

    // Points representing y = x^3 - x^2 + 2x + 1
    const x0 = new BN(0);
    const x1 = new BN(1);
    const x2 = new BN(2);
    const x3 = new BN(3);

    const y0 = new BN(1);
    const y1 = new BN(3);
    const y2 = new BN(9);
    const y3 = new BN(22);

    const points = [
      new Point(x0, y0, curve),
      new Point(x1, y1, curve),
      new Point(x2, y2, curve),
      new Point(x3, y3, curve),
    ];

    const interpolatedPoly = lagrangeInterpolatePolynomial(curve, points);

    // Verify that the polynomial passes through all points
    for (const point of points) {
      const evaluated = interpolatedPoly.polyEval(point.x);
      expect(evaluated.eq(point.y)).toBe(true);
    }
  });

  it('should handle points in any order', function () {
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);

    // Points representing y = 2x + 1
    const x0 = new BN(0);
    const x1 = new BN(1);
    const x2 = new BN(2);

    const y0 = new BN(1);
    const y1 = new BN(3);
    const y2 = new BN(5);

    // Create points in ascending x order
    const points1 = [
      new Point(x0, y0, curve),
      new Point(x1, y1, curve),
      new Point(x2, y2, curve),
    ];

    // Create same points in different order
    const points2 = [
      new Point(x2, y2, curve),
      new Point(x0, y0, curve),
      new Point(x1, y1, curve),
    ];

    const poly1 = lagrangeInterpolatePolynomial(curve, points1);
    const poly2 = lagrangeInterpolatePolynomial(curve, points2);

    // Both polynomials should be identical
    expect(poly1.polynomial).toHaveLength(poly2.polynomial.length);
    for (let i = 0; i < poly1.polynomial.length; i++) {
      expect(poly1.polynomial[i].eq(poly2.polynomial[i])).toBe(true);
    }
  });

  it('should interpolate constant polynomial when given single point', function () {
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);
    const x = new BN(1);
    const y = new BN(2);
    const point = new Point(x, y, curve);

    const interpolatedPoly = lagrangeInterpolatePolynomial(curve, [point]);

    // Should be a constant polynomial equal to the y-value
    expect(interpolatedPoly.polynomial).toHaveLength(1);
    expect(interpolatedPoly.polynomial[0].eq(y)).toBe(true);
  });

  it('should interpolate linear polynomial when given two points', function () {
    const curve = getKeyCurve(KEY_TYPE.SECP256K1);

    // Points representing y = x + 1
    const x0 = new BN(0);
    const x1 = new BN(1);

    const y0 = new BN(1);
    const y1 = new BN(2);

    const points = [new Point(x0, y0, curve), new Point(x1, y1, curve)];

    const interpolatedPoly = lagrangeInterpolatePolynomial(curve, points);

    // Should be a linear polynomial
    expect(interpolatedPoly.polynomial).toHaveLength(2);

    // Verify it passes through both points
    for (const point of points) {
      const evaluated = interpolatedPoly.polyEval(point.x);
      expect(evaluated.eq(point.y)).toBe(true);
    }
  });
});
