import { Field } from '@noble/curves/abstract/modular';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import type { ec as EC } from 'elliptic';

/**
 * Performs Lagrange interpolation for curve points directly on the elliptic curve.
 *
 * @param curve - The elliptic curve to use for operations
 * @param points - Array of curve points to interpolate
 * @param nodeIndexes - Array of indices corresponding to each curve point
 * @returns The interpolated curve point at x=0
 */
export function lagrangeInterpolationForPoints(
  curve: EC,
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
    const coefficient = computeLagrangeCoefficient(curve, i, nodeIndexes);
    result = result.add(points[i].multiply(coefficient));
  }

  return result;
}

/**
 * Computes the Lagrange coefficient for a single point at x=0.
 *
 * @param curve - The elliptic curve to use for operations
 * @param idx - Index of the current point
 * @param nodeIndexes - Array of all node indices
 * @returns The Lagrange coefficient for the point at index idx
 */
function computeLagrangeCoefficient(
  curve: EC,
  idx: number,
  nodeIndexes: bigint[],
): bigint {
  if (!curve.n) {
    throw new Error('Curve order is not defined');
  }

  const xi = nodeIndexes[idx];
  let coefficient = 1n;

  // Create a scalar field using the curve's order
  const curveOrder = BigInt(curve.n.toString());
  const fieldOps = Field(curveOrder);

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
