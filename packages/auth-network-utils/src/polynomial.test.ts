import BN from 'bn.js';
import { ec as EC } from 'elliptic';

import Polynomial, { PolynomialNoble } from './polynomial';
import type { ShareMap } from './polynomial';

const ec = new EC('secp256k1');
const curveN = ec.n as BN;
const nobleCurveN = BigInt(`0x${curveN.toString('hex')}`);

const coeffsBN = [new BN(1), new BN(2), new BN(3)]; // Represents 3x^2 + 2x + 1

describe('polynomial', () => {
  let polynomial: Polynomial;

  beforeEach(() => {
    polynomial = new Polynomial(coeffsBN, ec);
  });

  describe('constructor', () => {
    it('should initialize correctly with BN coefficients', () => {
      expect(polynomial.polynomial).toStrictEqual(coeffsBN);
      expect(polynomial.ecCurve).toBe(ec);
    });
  });

  describe('getThreshold', () => {
    it('should return the correct threshold (degree + 1)', () => {
      expect(polynomial.getThreshold()).toBe(coeffsBN.length);
    });
  });

  describe('polyEval', () => {
    it('should evaluate the polynomial correctly for BN input', () => {
      // Evaluate at x=2: 3*(2^2) + 2*(2) + 1 = 12 + 4 + 1 = 17
      const point = new BN(2);
      const expected = new BN(17);
      const result = polynomial.polyEval(point);
      expect(result.eq(expected)).toBe(true);
    });

    it('should evaluate the polynomial correctly for hex string input', () => {
      // Evaluate at x=3: 3*(3^2) + 2*(3) + 1 = 27 + 6 + 1 = 34
      const pointHex = '3';
      const expected = new BN(34);
      const result = polynomial.polyEval(pointHex);
      expect(result.eq(expected)).toBe(true);
    });

    it('should throw if curve order n is missing', () => {
      const mockCurve = { n: undefined } as EC;
      const polyWithBadCurve = new Polynomial(coeffsBN, mockCurve);
      const point = new BN(1);
      expect(() => polyWithBadCurve.polyEval(point)).toThrow(
        'Curve is not set',
      );
    });
  });

  describe('generateShares', () => {
    it('should generate correct shares for BN indexes', () => {
      const indexes = [new BN(1), new BN(2)];
      const shares = polynomial.generateShares(indexes);
      // y(1) = 3*1+2*1+1 = 6
      // y(2) = 3*4+2*2+1 = 12+4+1 = 17
      expect(shares[indexes[0].toString('hex', 64)].share.eqn(6)).toBe(true);
      expect(shares[indexes[1].toString('hex', 64)].share.eqn(17)).toBe(true);
    });

    it('should generate correct shares for number indexes', () => {
      const indexes = [1, 2];
      const shares = polynomial.generateShares(indexes);
      expect(shares[new BN(1).toString('hex', 64)].share.eqn(6)).toBe(true);
      expect(shares[new BN(2).toString('hex', 64)].share.eqn(17)).toBe(true);
    });

    it('should generate correct shares for hex string indexes', () => {
      const indexes = ['1', '2'];
      const shares = polynomial.generateShares(indexes);
      expect(shares[new BN(1).toString('hex', 64)].share.eqn(6)).toBe(true);
      expect(shares[new BN(2).toString('hex', 64)].share.eqn(17)).toBe(true);
    });

    it('should handle mixed index types', () => {
      const indexes: (BN | string)[] = [new BN(1), new BN(2), '3'];
      const shares = polynomial.generateShares(indexes);
      // y(3) = 3*9+2*3+1 = 27+6+1 = 34
      expect(shares[new BN(1).toString('hex', 64)].share.eqn(6)).toBe(true);
      expect(shares[new BN(2).toString('hex', 64)].share.eqn(17)).toBe(true);
      expect(shares[new BN(3).toString('hex', 64)].share.eqn(34)).toBe(true);
    });

    it('should throw if invalid share index', () => {
      const indexes = [1, Symbol('test')] as any;
      expect(() => polynomial.generateShares(indexes)).toThrow(
        'Invalid share index',
      );
    });
  });

  describe('polyEvalNoble', () => {
    it('should throw error if Noble implementation not initialized', () => {
      const bnPolynomial = new Polynomial(coeffsBN, ec);
      expect(() => bnPolynomial.polyEvalNoble(2n)).toThrow(
        'Noble implementation not initialized',
      );
    });
  });
});

describe('polynomial noble', () => {
  const coeffsBigInt = [1n, 2n, 3n]; // Represents 3x^2 + 2x + 1
  let noblePolynomial: PolynomialNoble;

  beforeEach(() => {
    noblePolynomial = new PolynomialNoble(coeffsBigInt, nobleCurveN);
  });

  describe('constructor', () => {
    it('should initialize correctly with BigInt coefficients', () => {
      expect(noblePolynomial.polynomial).toStrictEqual(coeffsBN);
      expect(noblePolynomial.ecCurve).toBeDefined();
    });
  });

  describe('polyEvalNoble', () => {
    it('should evaluate the polynomial correctly for BigInt input', () => {
      // Evaluate at x=2: 3*(2^2) + 2*(2) + 1 = 12 + 4 + 1 = 17
      const point = 2n;
      const expected = 17n;
      const result = noblePolynomial.polyEvalNoble(point);
      expect(result).toBe(expected);
    });

    it('should return 0 for empty polynomial', () => {
      const emptyPoly = new PolynomialNoble([], nobleCurveN);
      expect(emptyPoly.polyEvalNoble(5n)).toBe(0n);
    });
  });

  describe('generateShares', () => {
    it('should generate correct shares', () => {
      const indexes = [1n, 2n];
      const shares: ShareMap = noblePolynomial.generateShares(indexes);
      expect(shares[new BN(1).toString('hex', 64)].share.eqn(6)).toBe(true);
      expect(shares[new BN(2).toString('hex', 64)].share.eqn(17)).toBe(true);
    });
  });
});
