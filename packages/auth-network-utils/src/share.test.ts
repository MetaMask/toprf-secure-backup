import BN from 'bn.js';

import type { BNString, StringifiedType } from './interfaces';
import Share from './share';

describe('share', () => {
  const shareIndexHex: BNString = '1'; // Hex string for BN
  const shareValueHex: BNString = 'a1b2c3d4'; // Hex string for BN
  const shareIndexBN = new BN(shareIndexHex, 'hex');
  const shareValueBN = new BN(shareValueHex, 'hex');

  describe('constructor', () => {
    it('should correctly initialize share and shareIndex from hex strings', () => {
      const share = new Share(shareIndexHex, shareValueHex);
      expect(share.shareIndex.eq(shareIndexBN)).toBe(true);
      expect(share.share.eq(shareValueBN)).toBe(true);
    });

    it('should handle zero values', () => {
      const zeroShare = new Share('0', '0');
      expect(zeroShare.shareIndex.eqn(0)).toBe(true);
      expect(zeroShare.share.eqn(0)).toBe(true);
    });
  });

  describe('toJSON', () => {
    it('should return a JSON object with hex string representations (padded)', () => {
      const share = new Share(shareIndexHex, shareValueHex);
      const json = share.toJSON();

      const expectedIndex = shareIndexBN.toString('hex', 64);
      const expectedShare = shareValueBN.toString('hex', 64);

      expect(json).toStrictEqual({
        shareIndex: expectedIndex,
        share: expectedShare,
      });
      expect(json.shareIndex).toHaveLength(64);
      expect(json.share).toHaveLength(64);
    });

    it('should handle zero values correctly in toJSON', () => {
      const zeroShare = new Share('0', '0');
      const json = zeroShare.toJSON();
      const zeroPad64 = '0'.padStart(64, '0');

      expect(json).toStrictEqual({
        shareIndex: zeroPad64,
        share: zeroPad64,
      });
    });
  });

  describe('fromJSON', () => {
    it('should create a Share instance from a valid JSON object', () => {
      const json: StringifiedType = {
        shareIndex: shareIndexBN.toString('hex', 64),
        share: shareValueBN.toString('hex', 64),
      };
      const share = Share.fromJSON(json);

      expect(share).toBeInstanceOf(Share);
      expect(
        share.shareIndex.eq(new BN(json.shareIndex as BNString, 'hex')),
      ).toBe(true);
      expect(share.share.eq(new BN(json.share as BNString, 'hex'))).toBe(true);
    });

    it('should create a Share instance from JSON with zero values', () => {
      const zeroPad64 = '0'.padStart(64, '0');
      const json: StringifiedType = {
        shareIndex: zeroPad64,
        share: zeroPad64,
      };
      const share = Share.fromJSON(json);

      expect(share).toBeInstanceOf(Share);
      expect(share.shareIndex.eqn(0)).toBe(true);
      expect(share.share.eqn(0)).toBe(true);
    });
  });
});
