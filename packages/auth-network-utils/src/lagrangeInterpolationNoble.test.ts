import { secp256k1 } from '@noble/curves/secp256k1';

import {
  generateRandomPolynomialNoble,
  generateRandomScalar,
  lagrangeInterpolationForPoints,
  lagrangeInterpolationForScalars,
} from './lagrangeInterpolation';

describe('Noble Curves Lagrange Interpolation', () => {
  const curveN = secp256k1.CURVE.n;

  describe('generateRandomPolynomialNoble', () => {
    it('should generate random polynomial of correct degree', () => {
      const degree = 5;

      const result = generateRandomPolynomialNoble(curveN, degree);

      expect(result.polynomial).toHaveLength(degree + 1);
    });

    it('should generate random polynomial with provided secret', () => {
      const degree = 5;
      const secret = 12345678n;

      const result = generateRandomPolynomialNoble(curveN, degree, secret);

      expect(BigInt(result.polynomial[0].toString())).toBe(secret);
    });
  });

  describe('lagrangeInterpolationForScalars', () => {
    it('should reconstruct secret from scalar shares', () => {
      const degree = 3;
      const sharesRequired = degree + 1;
      const secret = 987654321n;

      const polynomial = generateRandomPolynomialNoble(curveN, degree, secret);

      const indices = Array.from({ length: sharesRequired }, (_, i) =>
        BigInt(i + 1),
      );
      const shares = indices.map((index) => polynomial.polyEvalNoble(index));

      const reconstructedSecret = lagrangeInterpolationForScalars(
        curveN,
        shares,
        indices,
      );

      expect(reconstructedSecret).toBe(secret);
    });

    it('should interpolate polynomial of any degree', () => {
      for (const degree of [1, 2, 5]) {
        const sharesRequired = degree + 1;
        const secret = generateRandomScalar(curveN);

        const polynomial = generateRandomPolynomialNoble(
          curveN,
          degree,
          secret,
        );

        const indices = Array.from({ length: sharesRequired }, (_, i) =>
          BigInt(i + 1),
        );
        const shares = indices.map((index) => polynomial.polyEvalNoble(index));

        const reconstructedSecret = lagrangeInterpolationForScalars(
          curveN,
          shares,
          indices,
        );

        expect(reconstructedSecret).toBe(secret);
      }
    });

    it('should work with any valid set of indices', () => {
      const degree = 3;
      const secret = 123456789n;

      const polynomial = generateRandomPolynomialNoble(curveN, degree, secret);

      const indices = [5n, 10n, 15n, 20n];
      const shares = indices.map((index) => polynomial.polyEvalNoble(index));

      const reconstructedSecret = lagrangeInterpolationForScalars(
        curveN,
        shares,
        indices,
      );

      expect(reconstructedSecret).toBe(secret);
    });

    it('should throw error when arrays have different lengths', () => {
      const shares = [1n, 2n, 3n];
      const indices = [1n, 2n];

      expect(() => {
        lagrangeInterpolationForScalars(curveN, shares, indices);
      }).toThrow('Values and nodeIndex arrays must have the same length');
    });

    it('should throw error with empty arrays', () => {
      expect(() => {
        lagrangeInterpolationForScalars(curveN, [], []);
      }).toThrow('Cannot interpolate with empty arrays');
    });
  });

  describe('lagrangeInterpolationForPoints', () => {
    it('should reconstruct a point from point shares', () => {
      const secretScalar = generateRandomScalar(curveN);
      const secretPoint = secp256k1.ProjectivePoint.BASE.multiply(secretScalar);
      const x1 = 1n;
      const x2 = 2n;
      const nodeIndexes = [x1, x2];

      // Generate points on the linear function y = base * (scalar + x)
      const points = nodeIndexes.map((nodeIndex) =>
        secp256k1.ProjectivePoint.BASE.multiply(secretScalar + nodeIndex),
      );

      const reconstructedPoint = lagrangeInterpolationForPoints(
        curveN,
        points,
        nodeIndexes,
      );

      expect(reconstructedPoint.equals(secretPoint)).toBe(true);
    });

    it('should work with more than minimum required points', () => {
      const secretScalar = generateRandomScalar(curveN);
      const secretPoint = secp256k1.ProjectivePoint.BASE.multiply(secretScalar);

      // Create more points than needed for interpolation
      const nodeIndexes = [1n, 2n, 3n, 4n];

      // Generate points on the linear function y = base * (scalar + x)
      const points = nodeIndexes.map((nodeIndex) =>
        secp256k1.ProjectivePoint.BASE.multiply(secretScalar + nodeIndex),
      );

      const reconstructedPoint = lagrangeInterpolationForPoints(
        curveN,
        points,
        nodeIndexes,
      );

      expect(reconstructedPoint.equals(secretPoint)).toBe(true);
    });

    it('should handle non-sequential indices', () => {
      const secretScalar = generateRandomScalar(curveN);
      const secretPoint = secp256k1.ProjectivePoint.BASE.multiply(secretScalar);

      // Use non-sequential indices
      const nodeIndexes = [5n, 10n, 15n];

      const points = nodeIndexes.map((nodeIndex) =>
        secp256k1.ProjectivePoint.BASE.multiply(secretScalar + nodeIndex),
      );

      const reconstructedPoint = lagrangeInterpolationForPoints(
        curveN,
        points,
        nodeIndexes,
      );

      expect(reconstructedPoint.equals(secretPoint)).toBe(true);
    });

    it('should throw error when arrays have different lengths', () => {
      const points = [
        secp256k1.ProjectivePoint.BASE.multiply(1n),
        secp256k1.ProjectivePoint.BASE.multiply(2n),
        secp256k1.ProjectivePoint.BASE.multiply(3n),
      ];
      const indices = [1n, 2n];

      expect(() => {
        lagrangeInterpolationForPoints(curveN, points, indices);
      }).toThrow('Values and nodeIndex arrays must have the same length');
    });

    it('should throw error with empty arrays', () => {
      expect(() => {
        lagrangeInterpolationForPoints(curveN, [], []);
      }).toThrow('Cannot interpolate with empty arrays');
    });
  });
});
