import BN from 'bn.js';
import type { ec as EC } from 'elliptic';

import { generate32BytesPrivateKeyBuffer } from './cryptoUtils';
import { generateEmptyBNArray } from './helpers';
import Point from './point';  
import Polynomial from './polynomial';
import type Share from './share';

/**
 *
 * @param shareIndexes
 * @param ecCurve
 */
function generatePrivateExcludingIndexes(shareIndexes: BN[], ecCurve: EC): BN {
  const key = new BN(generate32BytesPrivateKeyBuffer(ecCurve));
  if (shareIndexes.find((el) => el.eq(key))) {
    return generatePrivateExcludingIndexes(shareIndexes, ecCurve);
  }
  return key;
}

/**
 * Multiplies two polynomials (represented as arrays of BN) modulo mod
 * poly1 and poly2 are arrays where index 0 is the constant term
 *
 * @param poly1
 * @param poly2
 * @param mod
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
 * @param ecCurve
 * @param points
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
      const denom = points[i].x.sub(points[j].x).umod(ecCurve.n);
      // Compute the modular inverse of denom
      const denomInv = denom.invm(ecCurve.n);

      // The linear factor (x - x_j)/(x_i - x_j) is represented as [ -x_j * denomInv, 1 * denomInv ]
      const linearFactor = [
        // Constant term: -x_j/(x_i - x_j)
        points[j].x.neg().umod(ecCurve.n).mul(denomInv).umod(ecCurve.n),
        // Coefficient of x: 1/(x_i - x_j)
        denomInv,
      ];

      // Multiply the current Lagrange basis polynomial by this linear factor
      basisPoly = multiplyPolynomials(basisPoly, linearFactor, ecCurve.n);
    }

    // Multiply the basis polynomial by y_i and add it to the overall polynomial
    for (let k = 0; k < basisPoly.length; k++) {
      polyCoeffs[k] = polyCoeffs[k]
        .add(basisPoly[k].mul(points[i].y))
        .umod(ecCurve.n);
    }
  }

  return new Polynomial(polyCoeffs, ecCurve);
}

// generateRandomPolynomial - deterministicShares are assumed random
/**
 *
 * @param ecCurve
 * @param degree
 * @param secret
 * @param deterministicShares
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
    let shareIndex = generatePrivateExcludingIndexes([new BN(0)], ecCurve);
    while (points[shareIndex.toString('hex', 64)] !== undefined) {
      shareIndex = generatePrivateExcludingIndexes([new BN(0)], ecCurve);
    }
    points[shareIndex.toString('hex', 64)] = new Point(
      shareIndex,
      new BN(generate32BytesPrivateKeyBuffer(ecCurve)),
      ecCurve,
    );
  }
  points['0'] = new Point(new BN(0), actualS, ecCurve);
  return lagrangeInterpolatePolynomial(ecCurve, Object.values(points));
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
