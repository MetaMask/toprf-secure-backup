import type { ProjPointType } from "@noble/curves/abstract/weierstrass";
import BN from "bn.js";
import type { ec as EC } from "elliptic";
import Point from "./point.mjs";
import Polynomial from "./polynomial.mjs";
import type Share from "./share.mjs";
/**
 * Constructs the interpolating polynomial using Lagrange's formula
 * Given points (x_i, y_i), it returns the polynomial P(x) = Σ y_i * L_i(x)
 * where L_i(x) = Π_{j≠i} (x - x_j)/(x_i - x_j)
 *
 * @param ecCurve - The elliptic curve to use
 * @param points - The points to use
 * @returns The interpolating polynomial
 */
export declare function lagrangeInterpolatePolynomial(ecCurve: EC, points: Point[]): Polynomial;
/**
 * Generates a random polynomial
 *
 * @param ecCurve - The elliptic curve to use.
 * @param degree - The degree of the polynomial.
 * @param secret - The secret to use.
 * @param deterministicShares - The deterministic shares to use
 * @returns The polynomial
 */
export declare function generateRandomPolynomial(ecCurve: EC, degree: number, secret?: BN, deterministicShares?: Share[]): Polynomial;
/**
 * Generates a random polynomial using the Noble implementation
 *
 * @param curveN - The order of the curve as bigint
 * @param degree - The degree of the polynomial
 * @param secret - The secret to use
 * @returns The polynomial
 */
export declare function generateRandomPolynomialNoble(curveN: bigint, degree: number, secret?: bigint): Polynomial;
/**
 * Generates a random scalar for an elliptic curve
 *
 * @param curveN - The order of the curve (defaults to secp256k1 curve order)
 * @returns A random scalar (bigint) below the curve order
 */
export declare function generateRandomScalar(curveN?: bigint): bigint;
/**
 * Generic Lagrange interpolation function using Noble Curves for scalars and points
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param values - Array of values (either scalars or curve points) to interpolate
 * @param nodeIndexes - Array of indices corresponding to each value
 * @returns The interpolated value at x=0
 */
export declare function lagrangeInterpolationNoble<ValueType extends bigint | ProjPointType<bigint>>(curveN: bigint, values: ValueType[], nodeIndexes: bigint[]): ValueType;
/**
 * Lagrange interpolation for curve points on the elliptic curve.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param points - Array of curve points to interpolate
 * @param nodeIndexes - Array of indices corresponding to each curve point
 * @returns The interpolated curve point at x=0
 */
export declare function lagrangeInterpolationForPoints(curveN: bigint, points: ProjPointType<bigint>[], nodeIndexes: bigint[]): ProjPointType<bigint>;
/**
 * Lagrange interpolation for scalars in the field.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param scalars - Array of scalar values to interpolate
 * @param nodeIndexes - Array of indices corresponding to each scalar
 * @returns The interpolated scalar at x=0
 */
export declare function lagrangeInterpolationForScalars(curveN: bigint, scalars: bigint[], nodeIndexes: bigint[]): bigint;
/**
 * Reconstructs the secret from a set of shares using Lagrange interpolation
 *
 * @param ecCurve - The elliptic curve to use for operations
 * @param shares - Array of share values
 * @param nodeIndex - Array of corresponding node indices
 * @returns The reconstructed secret (constant term of the polynomial)
 */
export declare function lagrangeInterpolation(ecCurve: EC, shares: BN[], nodeIndex: BN[]): BN;
//# sourceMappingURL=lagrangeInterpolation.d.mts.map