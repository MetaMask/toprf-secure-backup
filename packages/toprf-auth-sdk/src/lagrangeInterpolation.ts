import { Field, getMinHashLength } from '@noble/curves/abstract/modular';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
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
 * Generic Lagrange interpolation function that can handle both scalars and points
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param values - Array of values (either scalars or curve points) to interpolate
 * @param nodeIndexes - Array of indices corresponding to each value
 * @returns The interpolated value at x=0
 */
export function lagrangeInterpolation<T extends bigint | ProjPointType<bigint>>(
  curveN: bigint,
  values: T[],
  nodeIndexes: bigint[],
): T {
  if (values.length !== nodeIndexes.length) {
    throw new Error('Values and nodeIndex arrays must have the same length');
  }

  if (values.length === 0) {
    throw new Error('Cannot interpolate with empty arrays');
  }

  const fieldOps = Field(curveN);
  const isScalar = typeof values[0] === 'bigint';
  let result = (isScalar ? 0n : secp256k1.ProjectivePoint.ZERO) as T;

  // Add contribution from each value
  for (let i = 0; i < values.length; i++) {
    // Calculate Lagrange coefficient
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
      result = fieldOps.add(result as bigint, term) as T;
    } else {
      const point = values[i] as ProjPointType<bigint>;
      const term = point.multiply(coefficient);
      result = (result as ProjPointType<bigint>).add(term) as T;
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
  return lagrangeInterpolation(curveN, points, nodeIndexes);
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
  return lagrangeInterpolation(curveN, scalars, nodeIndexes);
}
