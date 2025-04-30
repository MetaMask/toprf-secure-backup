import { Field, getMinHashLength } from '@noble/curves/abstract/modular';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import BN from 'bn.js';
import type { ec as EC } from 'elliptic';

import { generatePrivateKey } from './cryptoUtils';
import { generateEmptyBNArray } from './helpers';
import Point from './point';
import Polynomial, { PolynomialNoble } from './polynomial';
import type Share from './share';

// TODO: Replace Elliptic Curve with Noble Curves

/**
 * Generates a private key excluding the given indexes
 *
 * @param shareIndexes - The indexes to exclude
 * @param ecCurve - The elliptic curve to use
 * @returns The private key
 */
function generatePrivateExcludingIndexes(shareIndexes: BN[], ecCurve: EC): BN {
  const key = generatePrivateKey(ecCurve);
  if (shareIndexes.find((el) => el.eq(key))) {
    return generatePrivateExcludingIndexes(shareIndexes, ecCurve);
  }
  return key;
}

/**
 * Multiplies two polynomials (represented as arrays of BN) modulo mod
 * poly1 and poly2 are arrays where index 0 is the constant term
 *
 * @param poly1 - The first polynomial
 * @param poly2 - The second polynomial
 * @param mod - The modulus
 * @returns The product of the two polynomials modulo the modulus
 */
function multiplyPolynomials(poly1: BN[], poly2: BN[], mod: BN): BN[] {
  const result = generateEmptyBNArray(poly1.length + poly2.length - 1);
  for (let i = 0; i < poly1.length; i++) {
    for (let j = 0; j < poly2.length; j++) {
      result[i + j] = result[i + j].add(poly1[i].mul(poly2[j])).umod(mod);
    }
  }
  return result;
}

/**
 * Constructs the interpolating polynomial using Lagrange's formula
 * Given points (x_i, y_i), it returns the polynomial P(x) = Σ y_i * L_i(x)
 * where L_i(x) = Π_{j≠i} (x - x_j)/(x_i - x_j)
 *
 * @param ecCurve - The elliptic curve to use
 * @param points - The points to use
 * @returns The interpolating polynomial
 */
export function lagrangeInterpolatePolynomial(
  ecCurve: EC,
  points: Point[],
): Polynomial {
  const numPoints = points.length;
  const polyCoeffs = generateEmptyBNArray(numPoints);

  if (!ecCurve.n) {
    throw new Error('Curve is not set');
  }

  // For each point, compute its Lagrange basis polynomial
  for (let i = 0; i < numPoints; i++) {
    let basisPoly = [new BN(1)]; // L_i(x) = 1

    for (let j = 0; j < numPoints; j++) {
      if (j === i) {
        continue;
      }
      // Compute the denominator: (x_i - x_j) modulo the curve order
      const denom = points[i].xCoordinate
        .sub(points[j].xCoordinate)
        .umod(ecCurve.n);
      // Compute the modular inverse of denom
      const denomInv = denom.invm(ecCurve.n);

      // The linear factor (x - x_j)/(x_i - x_j) is represented as [ -x_j * denomInv, 1 * denomInv ]
      const linearFactor = [
        // Constant term: -x_j/(x_i - x_j)
        points[j].xCoordinate
          .neg()
          .umod(ecCurve.n)
          .mul(denomInv)
          .umod(ecCurve.n),
        // Coefficient of x: 1/(x_i - x_j)
        denomInv,
      ];

      // Multiply the current Lagrange basis polynomial by this linear factor
      basisPoly = multiplyPolynomials(basisPoly, linearFactor, ecCurve.n);
    }

    // Multiply the basis polynomial by y_i and add it to the overall polynomial
    for (let k = 0; k < basisPoly.length; k++) {
      polyCoeffs[k] = polyCoeffs[k]
        .add(basisPoly[k].mul(points[i].yCoordinate))
        .umod(ecCurve.n);
    }
  }

  return new Polynomial(polyCoeffs, ecCurve);
}

/**
 * Generates a random polynomial
 *
 * @param ecCurve - The elliptic curve to use.
 * @param degree - The degree of the polynomial.
 * @param secret - The secret to use.
 * @param deterministicShares - The deterministic shares to use
 * @returns The polynomial
 */
export function generateRandomPolynomial(
  ecCurve: EC,
  degree: number,
  secret?: BN,
  deterministicShares?: Share[],
): Polynomial {
  let actualS: BN;
  if (secret) {
    actualS = secret;
  } else {
    actualS = generatePrivateExcludingIndexes([new BN(0)], ecCurve);
  }

  if (!deterministicShares) {
    const poly = [actualS];
    for (let i = 0; i < degree; i += 1) {
      const share = generatePrivateExcludingIndexes(poly, ecCurve);
      poly.push(share);
    }
    return new Polynomial(poly, ecCurve);
  }
  if (!Array.isArray(deterministicShares)) {
    throw new Error(
      'deterministic shares in generateRandomPolynomial should be an array',
    );
  }

  if (deterministicShares.length > degree) {
    throw new Error(
      'deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness',
    );
  }
  const points: Record<string, Point> = {};
  deterministicShares.forEach((share) => {
    points[share.shareIndex.toString('hex', 64)] = new Point(
      share.shareIndex,
      share.share,
      ecCurve,
    );
  });
  for (let i = 0; i < degree - deterministicShares.length; i += 1) {
    const excludeIndexes = [new BN(0)];
    Object.keys(points).forEach((indexHex) => {
      excludeIndexes.push(new BN(indexHex, 'hex'));
    });

    const shareIndex = generatePrivateExcludingIndexes(excludeIndexes, ecCurve);
    points[shareIndex.toString('hex', 64)] = new Point(
      shareIndex,
      generatePrivateKey(ecCurve),
      ecCurve,
    );
  }
  points['0'] = new Point(new BN(0), actualS, ecCurve);
  return lagrangeInterpolatePolynomial(ecCurve, Object.values(points));
}

/**
 * Generates a random polynomial using the Noble implementation
 *
 * @param curveN - The order of the curve as bigint
 * @param degree - The degree of the polynomial
 * @param secret - The secret to use
 * @returns The polynomial
 */
export function generateRandomPolynomialNoble(
  curveN: bigint,
  degree: number,
  secret?: bigint,
): Polynomial {
  const secretBigInt = secret ?? generateRandomScalar(curveN);

  const coefficients: bigint[] = [secretBigInt];
  // Generate random coefficients for the higher-degree terms
  for (let i = 1; i <= degree; i++) {
    coefficients[i] = generateRandomScalar(curveN);
  }

  // Create a new Polynomial instance with Noble options
  return new PolynomialNoble(coefficients, curveN);
}

/**
 * Generates a random scalar for an elliptic curve
 *
 * @param curveN - The order of the curve (defaults to secp256k1 curve order)
 * @returns A random scalar (bigint) below the curve order
 */
export function generateRandomScalar(curveN = secp256k1.CURVE.n): bigint {
  const length = getMinHashLength(curveN);
  const rBytes = randomBytes(length);
  return bytesToNumberBE(rBytes) % curveN;
}

/**
 * Generic Lagrange interpolation function using Noble Curves for scalars and points
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param values - Array of values (either scalars or curve points) to interpolate
 * @param nodeIndexes - Array of indices corresponding to each value
 * @returns The interpolated value at x=0
 */
export function lagrangeInterpolationNoble<
  ValueType extends bigint | ProjPointType<bigint>,
>(curveN: bigint, values: ValueType[], nodeIndexes: bigint[]): ValueType {
  if (values.length !== nodeIndexes.length) {
    throw new Error('Values and nodeIndex arrays must have the same length');
  }

  if (values.length === 0) {
    throw new Error('Cannot interpolate with empty arrays');
  }

  const fieldOps = Field(curveN);
  const isScalar = typeof values[0] === 'bigint';
  let result = (isScalar ? 0n : secp256k1.ProjectivePoint.ZERO) as ValueType;

  // Add contribution from each value
  for (let i = 0; i < values.length; i++) {
    // Calculate Lagrange coefficient
    // TODO: Computing all Lagrange coefficients together can be more efficient
    // than computing them individually. Consider implementing this optimization
    // in the future if performance becomes critical.
    let numerator = 1n;
    let denominator = 1n;

    for (let j = 0; j < nodeIndexes.length; j++) {
      if (i === j) {
        continue;
      }

      const xi = nodeIndexes[i];
      const xj = nodeIndexes[j];

      // Computing (0 - xj) for the numerator
      const numeratorTerm = fieldOps.neg(xj);

      // Computing (xi - xj) for the denominator
      const denominatorTerm = fieldOps.sub(xi, xj);

      numerator = fieldOps.mul(numerator, numeratorTerm);
      denominator = fieldOps.mul(denominator, denominatorTerm);
    }
    // Compute coefficient with a single inversion
    const coefficient = fieldOps.mul(numerator, fieldOps.inv(denominator));

    // Apply coefficient to the current value and add to result
    if (isScalar) {
      const scalar = values[i] as bigint;
      const term = fieldOps.mul(scalar, coefficient);
      result = fieldOps.add(result as bigint, term) as ValueType;
    } else {
      const point = values[i] as ProjPointType<bigint>;
      const term = point.multiply(coefficient);
      result = (result as ProjPointType<bigint>).add(term) as ValueType;
    }
  }

  return result;
}

/**
 * Lagrange interpolation for curve points on the elliptic curve.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param points - Array of curve points to interpolate
 * @param nodeIndexes - Array of indices corresponding to each curve point
 * @returns The interpolated curve point at x=0
 */
export function lagrangeInterpolationForPoints(
  curveN: bigint,
  points: ProjPointType<bigint>[],
  nodeIndexes: bigint[],
): ProjPointType<bigint> {
  return lagrangeInterpolationNoble(curveN, points, nodeIndexes);
}

/**
 * Lagrange interpolation for scalars in the field.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param scalars - Array of scalar values to interpolate
 * @param nodeIndexes - Array of indices corresponding to each scalar
 * @returns The interpolated scalar at x=0
 */
export function lagrangeInterpolationForScalars(
  curveN: bigint,
  scalars: bigint[],
  nodeIndexes: bigint[],
): bigint {
  return lagrangeInterpolationNoble(curveN, scalars, nodeIndexes);
}

/**
 * Reconstructs the secret from a set of shares using Lagrange interpolation
 *
 * @param ecCurve - The elliptic curve to use for operations
 * @param shares - Array of share values
 * @param nodeIndex - Array of corresponding node indices
 * @returns The reconstructed secret (constant term of the polynomial)
 */
export function lagrangeInterpolation(
  ecCurve: EC,
  shares: BN[],
  nodeIndex: BN[],
): BN {
  if (shares.length !== nodeIndex.length) {
    throw new Error(
      'shares not equal to nodeIndex length in lagrangeInterpolation',
    );
  }

  // Convert shares and indices to points
  const points = shares.map(
    (share, i) => new Point(nodeIndex[i], share, ecCurve),
  );

  // Interpolate the polynomial and get the constant term (secret)
  const polynomial = lagrangeInterpolatePolynomial(ecCurve, points);
  return polynomial.polynomial[0];
}
