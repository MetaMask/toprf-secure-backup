import BN from "bn.js";
import { ec as EC } from "elliptic";
import type { BNString } from "./interfaces.mjs";
import Share from "./share.mjs";
export type ShareMap = {
    [x: string]: Share;
};
/**
 * Class representing a polynomial over a finite field
 */
declare class Polynomial {
    #private;
    polynomial: BN[];
    ecCurve: EC;
    /**
     * Creates a new polynomial
     *
     * @param polynomial - polynomial coefficients (BN)
     * @param ecCurve - elliptic curve instance
     * @param nobleOptions - Optional parameters for Noble curves implementation
     * @param nobleOptions.curveN - The order of the curve as bigint
     */
    constructor(polynomial: BN[] | bigint[], ecCurve: EC, nobleOptions?: {
        curveN: bigint;
    });
    /**
     * @returns - threshold of the polynomial.
     */
    getThreshold(): number;
    /**
     * Evaluates the polynomial at a given point.
     *
     * @param point - point to evaluate the polynomial at.
     * @returns - value of the polynomial at the given point.
     */
    polyEval(point: BNString): BN;
    /**
     * Evaluates the polynomial at a given point using the Noble implementation.
     * This method uses bigint arithmetic for better performance and compatibility
     * with the Noble Curves library.
     *
     * @param point - The point at which to evaluate the polynomial, as a bigint
     * @returns The value of the polynomial at the given point
     * @throws Error if the Noble implementation is not initialized
     */
    polyEvalNoble(point: bigint): bigint;
    /**
     * Generates shares from the polynomial.
     *
     * @param shareIndexes - indexes to generate shares for on the polynomial.
     * @returns - map of sharesIndexes to shares.
     */
    generateShares(shareIndexes: (BNString | bigint)[]): ShareMap;
}
export default Polynomial;
/**
 * Class representing a polynomial over a finite field using the Noble implementation
 */
export declare class PolynomialNoble extends Polynomial {
    /**
     * Creates a new polynomial using the Noble implementation
     *
     * @param coefficients - The coefficients of the polynomial
     * @param curveN - The order of the curve as bigint
     */
    constructor(coefficients: bigint[], curveN: bigint);
}
//# sourceMappingURL=polynomial.d.mts.map