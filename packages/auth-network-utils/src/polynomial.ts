import { Field } from '@noble/curves/abstract/modular';
import BN from 'bn.js';
import { ec as EC } from 'elliptic';

import type { BNString } from './interfaces';
import Share from './share';

export type ShareMap = {
  [x: string]: Share;
};

/**
 * Class representing a polynomial over a finite field
 */
class Polynomial {
  polynomial: BN[];

  ecCurve: EC;

  // Noble curves implementation properties
  readonly #coefficients?: bigint[];

  readonly #fieldOps?: ReturnType<typeof Field>;

  /**
   * Creates a new polynomial
   *
   * @param polynomial - polynomial coefficients (BN)
   * @param ecCurve - elliptic curve instance
   * @param nobleOptions - Optional parameters for Noble curves implementation
   * @param nobleOptions.curveN - The order of the curve as bigint
   */
  constructor(
    polynomial: BN[] | bigint[],
    ecCurve: EC,
    nobleOptions?: { curveN: bigint },
  ) {
    // Handle Noble implementation if specified
    if (nobleOptions) {
      this.#coefficients = polynomial as bigint[];
      this.#fieldOps = Field(nobleOptions.curveN);
      // Convert bigint to BN for backward compatibility
      this.polynomial = this.#coefficients.map(
        (coefficient) => new BN(coefficient.toString()),
      );
    } else {
      // Original implementation with BN
      this.polynomial = polynomial as BN[];
    }
    this.ecCurve = ecCurve;
  }

  /**
   * @returns - threshold of the polynomial.
   */
  getThreshold(): number {
    return this.polynomial.length;
  }

  /**
   * Evaluates the polynomial at a given point.
   *
   * @param point - point to evaluate the polynomial at.
   * @returns - value of the polynomial at the given point.
   */
  polyEval(point: BNString): BN {
    const tmpX = new BN(point, 'hex');
    let xi = new BN(tmpX);
    let sum = new BN(0);
    sum = sum.add(this.polynomial[0]);

    const { n } = this.ecCurve;
    if (!n) {
      throw new Error('Curve is not set');
    }

    for (const coeff of this.polynomial.slice(1)) {
      const tmp = xi.mul(coeff);
      sum = sum.add(tmp);
      sum = sum.umod(n);
      xi = xi.mul(new BN(tmpX));
      xi = xi.umod(n);
    }
    return sum;
  }

  /**
   * Evaluates the polynomial at a given point using the Noble implementation.
   * This method uses bigint arithmetic for better performance and compatibility
   * with the Noble Curves library.
   *
   * @param point - The point at which to evaluate the polynomial, as a bigint
   * @returns The value of the polynomial at the given point
   * @throws Error if the Noble implementation is not initialized
   */
  polyEvalNoble(point: bigint): bigint {
    if (!this.#coefficients || !this.#fieldOps) {
      throw new Error('Noble implementation not initialized');
    }

    if (this.#coefficients.length === 0) {
      return 0n;
    }

    let result = this.#coefficients[0];
    let power = point;

    for (let i = 1; i < this.#coefficients.length; i++) {
      // Add term: coefficient * point^i
      result = this.#fieldOps.add(
        result,
        this.#fieldOps.mul(this.#coefficients[i], power),
      );
      // Update power for next iteration: point^(i+1)
      power = this.#fieldOps.mul(power, point);
    }

    return result;
  }

  /**
   * Generates shares from the polynomial.
   *
   * @param shareIndexes - indexes to generate shares for on the polynomial.
   * @returns - map of sharesIndexes to shares.
   */
  generateShares(shareIndexes: (BNString | bigint | number | BN)[]): ShareMap {
    const newShareIndexes = shareIndexes.map((index) => {
      if (typeof index === 'bigint') {
        return new BN(index.toString());
      }
      if (typeof index === 'number') {
        return new BN(index);
      }
      if (index instanceof BN) {
        return index;
      }
      if (typeof index === 'string') {
        return new BN(index, 'hex');
      }
      throw new Error('Invalid share index');
    });

    const shares: ShareMap = {};
    for (const index of newShareIndexes) {
      shares[index.toString('hex', 64)] = new Share(
        index,
        this.polyEval(index),
      );
    }
    return shares;
  }
}

export default Polynomial;

/**
 * Class representing a polynomial over a finite field using the Noble implementation
 */
export class PolynomialNoble extends Polynomial {
  /**
   * Creates a new polynomial using the Noble implementation
   *
   * @param coefficients - The coefficients of the polynomial
   * @param curveN - The order of the curve as bigint
   */
  constructor(coefficients: bigint[], curveN: bigint) {
    // elliptic curve instance just for compatibility
    const ecCurve = new EC('secp256k1');
    super(coefficients, ecCurve, { curveN });
  }
}
