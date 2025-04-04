"use strict";
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _Polynomial_coefficients, _Polynomial_fieldOps;
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolynomialNoble = void 0;
const modular_1 = require("@noble/curves/abstract/modular");
const bn_js_1 = __importDefault(require("bn.js"));
const elliptic_1 = require("elliptic");
const share_1 = __importDefault(require("./share.cjs"));
/**
 * Class representing a polynomial over a finite field
 */
class Polynomial {
    /**
     * Creates a new polynomial
     *
     * @param polynomial - polynomial coefficients (BN)
     * @param ecCurve - elliptic curve instance
     * @param nobleOptions - Optional parameters for Noble curves implementation
     * @param nobleOptions.curveN - The order of the curve as bigint
     */
    constructor(polynomial, ecCurve, nobleOptions) {
        // Noble curves implementation properties
        _Polynomial_coefficients.set(this, void 0);
        _Polynomial_fieldOps.set(this, void 0);
        // Handle Noble implementation if specified
        if (nobleOptions) {
            __classPrivateFieldSet(this, _Polynomial_coefficients, polynomial, "f");
            __classPrivateFieldSet(this, _Polynomial_fieldOps, (0, modular_1.Field)(nobleOptions.curveN), "f");
            // Convert bigint to BN for backward compatibility
            this.polynomial = __classPrivateFieldGet(this, _Polynomial_coefficients, "f").map((coefficient) => new bn_js_1.default(coefficient.toString()));
        }
        else {
            // Original implementation with BN
            this.polynomial = polynomial;
        }
        this.ecCurve = ecCurve;
    }
    /**
     * @returns - threshold of the polynomial.
     */
    getThreshold() {
        return this.polynomial.length;
    }
    /**
     * Evaluates the polynomial at a given point.
     *
     * @param point - point to evaluate the polynomial at.
     * @returns - value of the polynomial at the given point.
     */
    polyEval(point) {
        const tmpX = new bn_js_1.default(point, 'hex');
        let xi = new bn_js_1.default(tmpX);
        let sum = new bn_js_1.default(0);
        sum = sum.add(this.polynomial[0]);
        const { n } = this.ecCurve;
        if (!n) {
            throw new Error('Curve is not set');
        }
        for (const coeff of this.polynomial.slice(1)) {
            const tmp = xi.mul(coeff);
            sum = sum.add(tmp);
            sum = sum.umod(n);
            xi = xi.mul(new bn_js_1.default(tmpX));
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
    polyEvalNoble(point) {
        if (!__classPrivateFieldGet(this, _Polynomial_coefficients, "f") || !__classPrivateFieldGet(this, _Polynomial_fieldOps, "f")) {
            throw new Error('Noble implementation not initialized');
        }
        if (__classPrivateFieldGet(this, _Polynomial_coefficients, "f").length === 0) {
            return 0n;
        }
        let result = __classPrivateFieldGet(this, _Polynomial_coefficients, "f")[0];
        let power = point;
        for (let i = 1; i < __classPrivateFieldGet(this, _Polynomial_coefficients, "f").length; i++) {
            // Add term: coefficient * point^i
            result = __classPrivateFieldGet(this, _Polynomial_fieldOps, "f").add(result, __classPrivateFieldGet(this, _Polynomial_fieldOps, "f").mul(__classPrivateFieldGet(this, _Polynomial_coefficients, "f")[i], power));
            // Update power for next iteration: point^(i+1)
            power = __classPrivateFieldGet(this, _Polynomial_fieldOps, "f").mul(power, point);
        }
        return result;
    }
    /**
     * Generates shares from the polynomial.
     *
     * @param shareIndexes - indexes to generate shares for on the polynomial.
     * @returns - map of sharesIndexes to shares.
     */
    generateShares(shareIndexes) {
        const newShareIndexes = shareIndexes.map((index) => {
            if (typeof index === 'bigint') {
                return new bn_js_1.default(index.toString());
            }
            if (typeof index === 'number') {
                return new bn_js_1.default(index);
            }
            if (index instanceof bn_js_1.default) {
                return index;
            }
            if (typeof index === 'string') {
                return new bn_js_1.default(index, 'hex');
            }
            return index;
        });
        const shares = {};
        for (const index of newShareIndexes) {
            shares[index.toString('hex', 64)] = new share_1.default(index, this.polyEval(index));
        }
        return shares;
    }
}
_Polynomial_coefficients = new WeakMap(), _Polynomial_fieldOps = new WeakMap();
exports.default = Polynomial;
/**
 * Class representing a polynomial over a finite field using the Noble implementation
 */
class PolynomialNoble extends Polynomial {
    /**
     * Creates a new polynomial using the Noble implementation
     *
     * @param coefficients - The coefficients of the polynomial
     * @param curveN - The order of the curve as bigint
     */
    constructor(coefficients, curveN) {
        // elliptic curve instance just for compatibility
        const ecCurve = new elliptic_1.ec('secp256k1');
        super(coefficients, ecCurve, { curveN });
    }
}
exports.PolynomialNoble = PolynomialNoble;
//# sourceMappingURL=polynomial.cjs.map