"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.lagrangeInterpolation = exports.lagrangeInterpolationForScalars = exports.lagrangeInterpolationForPoints = exports.lagrangeInterpolationNoble = exports.generateRandomScalar = exports.generateRandomPolynomialNoble = exports.generateRandomPolynomial = exports.lagrangeInterpolatePolynomial = void 0;
const modular_1 = require("@noble/curves/abstract/modular");
const utils_1 = require("@noble/curves/abstract/utils");
const secp256k1_1 = require("@noble/curves/secp256k1");
const utils_2 = require("@noble/hashes/utils");
const bn_js_1 = __importDefault(require("bn.js"));
const cryptoUtils_1 = require("./cryptoUtils.cjs");
const helpers_1 = require("./helpers.cjs");
const point_1 = __importDefault(require("./point.cjs"));
const polynomial_1 = __importStar(require("./polynomial.cjs"));
// TODO: Replace Elliptic Curve with Noble Curves
/**
 * Generates a private key excluding the given indexes
 *
 * @param shareIndexes - The indexes to exclude
 * @param ecCurve - The elliptic curve to use
 * @returns The private key
 */
function generatePrivateExcludingIndexes(shareIndexes, ecCurve) {
    const key = new bn_js_1.default((0, cryptoUtils_1.generate32BytesPrivateKeyBuffer)(ecCurve));
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
function multiplyPolynomials(poly1, poly2, mod) {
    const result = (0, helpers_1.generateEmptyBNArray)(poly1.length + poly2.length - 1);
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
function lagrangeInterpolatePolynomial(ecCurve, points) {
    const numPoints = points.length;
    const polyCoeffs = (0, helpers_1.generateEmptyBNArray)(numPoints);
    if (!ecCurve.n) {
        throw new Error('Curve is not set');
    }
    // For each point, compute its Lagrange basis polynomial
    for (let i = 0; i < numPoints; i++) {
        let basisPoly = [new bn_js_1.default(1)]; // L_i(x) = 1
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
    return new polynomial_1.default(polyCoeffs, ecCurve);
}
exports.lagrangeInterpolatePolynomial = lagrangeInterpolatePolynomial;
/**
 * Generates a random polynomial
 *
 * @param ecCurve - The elliptic curve to use.
 * @param degree - The degree of the polynomial.
 * @param secret - The secret to use.
 * @param deterministicShares - The deterministic shares to use
 * @returns The polynomial
 */
function generateRandomPolynomial(ecCurve, degree, secret, deterministicShares) {
    let actualS;
    if (secret) {
        actualS = secret;
    }
    else {
        actualS = generatePrivateExcludingIndexes([new bn_js_1.default(0)], ecCurve);
    }
    if (!deterministicShares) {
        const poly = [actualS];
        for (let i = 0; i < degree; i += 1) {
            const share = generatePrivateExcludingIndexes(poly, ecCurve);
            poly.push(share);
        }
        return new polynomial_1.default(poly, ecCurve);
    }
    if (!Array.isArray(deterministicShares)) {
        throw new Error('deterministic shares in generateRandomPolynomial should be an array');
    }
    if (deterministicShares.length > degree) {
        throw new Error('deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness');
    }
    const points = {};
    deterministicShares.forEach((share) => {
        points[share.shareIndex.toString('hex', 64)] = new point_1.default(share.shareIndex, share.share, ecCurve);
    });
    for (let i = 0; i < degree - deterministicShares.length; i += 1) {
        let shareIndex = generatePrivateExcludingIndexes([new bn_js_1.default(0)], ecCurve);
        while (points[shareIndex.toString('hex', 64)] !== undefined) {
            shareIndex = generatePrivateExcludingIndexes([new bn_js_1.default(0)], ecCurve);
        }
        points[shareIndex.toString('hex', 64)] = new point_1.default(shareIndex, new bn_js_1.default((0, cryptoUtils_1.generate32BytesPrivateKeyBuffer)(ecCurve)), ecCurve);
    }
    points['0'] = new point_1.default(new bn_js_1.default(0), actualS, ecCurve);
    return lagrangeInterpolatePolynomial(ecCurve, Object.values(points));
}
exports.generateRandomPolynomial = generateRandomPolynomial;
/**
 * Generates a random polynomial using the Noble implementation
 *
 * @param curveN - The order of the curve as bigint
 * @param degree - The degree of the polynomial
 * @param secret - The secret to use
 * @returns The polynomial
 */
function generateRandomPolynomialNoble(curveN, degree, secret) {
    const secretBigInt = secret ?? generateRandomScalar(curveN);
    const coefficients = [secretBigInt];
    // Generate random coefficients for the higher-degree terms
    for (let i = 1; i <= degree; i++) {
        coefficients[i] = generateRandomScalar(curveN);
    }
    // Create a new Polynomial instance with Noble options
    return new polynomial_1.PolynomialNoble(coefficients, curveN);
}
exports.generateRandomPolynomialNoble = generateRandomPolynomialNoble;
/**
 * Generates a random scalar for an elliptic curve
 *
 * @param curveN - The order of the curve (defaults to secp256k1 curve order)
 * @returns A random scalar (bigint) below the curve order
 */
function generateRandomScalar(curveN = secp256k1_1.secp256k1.CURVE.n) {
    const length = (0, modular_1.getMinHashLength)(curveN);
    const rBytes = (0, utils_2.randomBytes)(length);
    return (0, utils_1.bytesToNumberBE)(rBytes) % curveN;
}
exports.generateRandomScalar = generateRandomScalar;
/**
 * Generic Lagrange interpolation function using Noble Curves for scalars and points
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param values - Array of values (either scalars or curve points) to interpolate
 * @param nodeIndexes - Array of indices corresponding to each value
 * @returns The interpolated value at x=0
 */
function lagrangeInterpolationNoble(curveN, values, nodeIndexes) {
    if (values.length !== nodeIndexes.length) {
        throw new Error('Values and nodeIndex arrays must have the same length');
    }
    if (values.length === 0) {
        throw new Error('Cannot interpolate with empty arrays');
    }
    const fieldOps = (0, modular_1.Field)(curveN);
    const isScalar = typeof values[0] === 'bigint';
    let result = (isScalar ? 0n : secp256k1_1.secp256k1.ProjectivePoint.ZERO);
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
            const scalar = values[i];
            const term = fieldOps.mul(scalar, coefficient);
            result = fieldOps.add(result, term);
        }
        else {
            const point = values[i];
            const term = point.multiply(coefficient);
            result = result.add(term);
        }
    }
    return result;
}
exports.lagrangeInterpolationNoble = lagrangeInterpolationNoble;
/**
 * Lagrange interpolation for curve points on the elliptic curve.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param points - Array of curve points to interpolate
 * @param nodeIndexes - Array of indices corresponding to each curve point
 * @returns The interpolated curve point at x=0
 */
function lagrangeInterpolationForPoints(curveN, points, nodeIndexes) {
    return lagrangeInterpolationNoble(curveN, points, nodeIndexes);
}
exports.lagrangeInterpolationForPoints = lagrangeInterpolationForPoints;
/**
 * Lagrange interpolation for scalars in the field.
 *
 * @param curveN - The order of the elliptic curve as a bigint
 * @param scalars - Array of scalar values to interpolate
 * @param nodeIndexes - Array of indices corresponding to each scalar
 * @returns The interpolated scalar at x=0
 */
function lagrangeInterpolationForScalars(curveN, scalars, nodeIndexes) {
    return lagrangeInterpolationNoble(curveN, scalars, nodeIndexes);
}
exports.lagrangeInterpolationForScalars = lagrangeInterpolationForScalars;
/**
 * Reconstructs the secret from a set of shares using Lagrange interpolation
 *
 * @param ecCurve - The elliptic curve to use for operations
 * @param shares - Array of share values
 * @param nodeIndex - Array of corresponding node indices
 * @returns The reconstructed secret (constant term of the polynomial)
 */
function lagrangeInterpolation(ecCurve, shares, nodeIndex) {
    if (shares.length !== nodeIndex.length) {
        throw new Error('shares not equal to nodeIndex length in lagrangeInterpolation');
    }
    // Convert shares and indices to points
    const points = shares.map((share, i) => new point_1.default(nodeIndex[i], share, ecCurve));
    // Interpolate the polynomial and get the constant term (secret)
    const polynomial = lagrangeInterpolatePolynomial(ecCurve, points);
    return polynomial.polynomial[0];
}
exports.lagrangeInterpolation = lagrangeInterpolation;
//# sourceMappingURL=lagrangeInterpolation.cjs.map