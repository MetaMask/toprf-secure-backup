import BN from 'bn.js';
import { ec as EC } from 'elliptic';

import type { BNString } from './interfaces';
import Point from './point';

const ec = new EC('secp256k1');

describe('point', () => {
  const xHex: BNString = '1a2b3c';
  const yHex: BNString = 'd4e5f6';
  const xBN = new BN(xHex, 'hex');
  const yBN = new BN(yHex, 'hex');

  describe('constructor', () => {
    it('should correctly initialize coordinates and curve', () => {
      const point = new Point(xHex, yHex, ec);
      expect(point.xCoordinate.eq(xBN)).toBe(true);
      expect(point.yCoordinate.eq(yBN)).toBe(true);
      expect(point.ecCurve).toBe(ec);
    });

    it('should handle zero coordinates', () => {
      const point = new Point('0', '0', ec);
      expect(point.xCoordinate.eqn(0)).toBe(true);
      expect(point.yCoordinate.eqn(0)).toBe(true);
    });
  });

  describe('encode', () => {
    let point: Point;

    beforeEach(() => {
      // Use curve's generator point for simplicity in encoding tests
      const G = ec.g;
      point = new Point(G.getX().toString('hex'), G.getY().toString('hex'), ec);
      // keyFromPublic requires hex strings for coordinates
      // Use the same padding as the encode method uses internally
      // keyPair = ec.keyFromPublic({ // No longer needed
      //   x: point.xCoordinate.toString('hex', 64),
      //   y: point.yCoordinate.toString('hex', 64),
      // });
    });

    it('should encode the point in uncompressed format with enc="arr"', () => {
      const encoded = point.encode('arr');
      const expectedX = point.xCoordinate.toString('hex', 64);
      const expectedY = point.yCoordinate.toString('hex', 64);
      const expectedBuffer = Buffer.concat([
        Buffer.from('04', 'hex'),
        Buffer.from(expectedX, 'hex'),
        Buffer.from(expectedY, 'hex'),
      ]);

      expect(encoded).toBeInstanceOf(Buffer);
      expect(encoded.equals(expectedBuffer)).toBe(true);
    });

    it('should encode the point in compressed format with enc="elliptic-compressed"', () => {
      const encodedBuffer = point.encode('elliptic-compressed');

      const internalKeyPair = point.ecCurve.keyFromPublic(
        {
          x: point.xCoordinate.toString('hex', 64),
          y: point.yCoordinate.toString('hex', 64),
        },
        'hex',
      );
      const expectedHex = internalKeyPair.getPublic(true, 'hex');
      const encodedHex = encodedBuffer.toString('hex');
      expect(encodedHex).toBe(expectedHex);

      const expectedBuffer = Buffer.from(expectedHex, 'hex');
      expect(encodedBuffer.equals(expectedBuffer)).toBe(true);
    });

    it('should throw an error for an invalid encoding type', () => {
      expect(() => point.encode('invalid-encoding')).toThrow(
        "encoding doesn't exist in Point",
      );
    });
  });
});
