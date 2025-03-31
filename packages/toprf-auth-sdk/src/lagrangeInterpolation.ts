import { Field } from '@noble/curves/abstract/modular';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';

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
