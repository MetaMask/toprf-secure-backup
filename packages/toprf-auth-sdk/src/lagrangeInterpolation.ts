import { Field } from '@noble/curves/abstract/modular';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import type BN from 'bn.js';

/**
 * A class representing a polynomial over the scalar field of the curve
 */
export class Polynomial {
  /** The coefficients of the polynomial */
  coefficients: bigint[];

  /** The order of the curve */
  curveN: bigint;

  /** Field operations helper */
  fieldOps: ReturnType<typeof Field>;

  /**
   * @param coefficients - The coefficients of the polynomial, with coefficients[0] being the constant term
   * @param curveN - The curve order
   */
  constructor(coefficients: bigint[], curveN: bigint) {
    this.coefficients = coefficients;
    this.curveN = curveN;
    this.fieldOps = Field(curveN);
  }

  /**
   * Evaluates the polynomial at a given point
   *
   * @param point - The point to evaluate at
   * @returns The value of the polynomial at point
   */
  evaluate(point: bigint): bigint {
    if (this.coefficients.length === 0) {
      return 0n;
    }

    let result = this.coefficients[0];
    let power = point;

    for (let i = 1; i < this.coefficients.length; i++) {
      // Add term: coefficient * point^i
      result = this.fieldOps.add(
        result,
        this.fieldOps.mul(this.coefficients[i], power),
      );
      // Update power for next iteration: point^(i+1)
      power = this.fieldOps.mul(power, point);
    }

    return result;
  }
}

/**
 * Generates a random scalar for an elliptic curve
 *
 * @param curveN - The order of the curve (defaults to secp256k1 curve order)
 * @returns A random scalar (bigint) below the curve order
 */
function generateRandomScalar(curveN = secp256k1.CURVE.n): bigint {
  const length = getMinHashLength(curveN);
  const rBytes = randomBytes(length);
  return bytesToNumberBE(rBytes) % curveN;
}

/**
 * Generates a random polynomial with a specified constant term
 *
 * @param curveN - The order of the curve
 * @param degree - The degree of the polynomial to generate
 * @param secret - Optional. The constant term of the polynomial. If not provided, a random one will be generated
 * @returns A polynomial with the given constant term and random other coefficients
 */
export function generateRandomPolynomial(
  curveN: bigint,
  degree: number,
  secret?: bigint | BN,
): Polynomial {
  const coefficients: bigint[] = [];

  // Set the constant term
  if (secret) {
    coefficients[0] =
      typeof secret === 'bigint' ? secret : BigInt(secret.toString());
  } else {
    coefficients[0] = generateRandomScalar(curveN);
  }

  // Generate random coefficients for the higher-degree terms
  for (let i = 1; i <= degree; i++) {
    coefficients[i] = generateRandomScalar(curveN);
  }

  return new Polynomial(coefficients, curveN);
}

/**
 * Performs Lagrange interpolation for curve points directly on the elliptic curve.
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
  if (points.length !== nodeIndexes.length) {
    throw new Error('Points and nodeIndex arrays must have the same length');
  }

  if (points.length === 0) {
    throw new Error('Cannot interpolate with empty arrays');
  }

  if (points.length === 1) {
    return points[0];
  }

  let result: ProjPointType<bigint> = secp256k1.ProjectivePoint.ZERO;

  // Add contribution from each point
  for (let i = 0; i < points.length; i++) {
    const coefficient = computeLagrangeCoefficient(curveN, i, nodeIndexes);
    result = result.add(points[i].multiply(coefficient));
  }

  return result;
}

/**
 * Computes the Lagrange coefficient for a single point at x=0.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param idx - Index of the current point
 * @param nodeIndexes - Array of all node indices
 * @returns The Lagrange coefficient for the point at index idx
 */
function computeLagrangeCoefficient(
  curveN: bigint,
  idx: number,
  nodeIndexes: bigint[],
): bigint {
  const xi = nodeIndexes[idx];
  let coefficient = 1n;

  // Create a scalar field using the curve's order
  const fieldOps = Field(curveN);

  for (let j = 0; j < nodeIndexes.length; j++) {
    if (idx === j) {
      continue;
    }

    const xj = nodeIndexes[j];

    // Computing (0 - xj) / (xi - xj) mod n
    const numerator = fieldOps.neg(xj); // 0 - xj
    const denominator = fieldOps.sub(xi, xj); // xi - xj

    // Calculate the term: numerator / denominator = -xj / (xi - xj)
    const term = fieldOps.mul(numerator, fieldOps.inv(denominator));

    // Multiply into the running coefficient
    coefficient = fieldOps.mul(coefficient, term);
  }

  return coefficient;
}
