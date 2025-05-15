import type { Ecies } from '@toruslabs/eccrypto';
import BN from 'bn.js';
import { ec as EC } from 'elliptic';

import {
  derivePubKey,
  encParamsHexToBuf,
  encryptedParamsBufToHex,
  generatePrivateKey,
  getSecp256K1Curve,
  toChecksumAddress,
  uint8ArrayToHex,
} from './cryptoUtils';
import type { EciesHex } from './interfaces';

describe('crypto utils', function () {
  let ec: EC;

  beforeAll(() => {
    ec = getSecp256K1Curve();
  });

  describe('getSecp256K1Curve', () => {
    it('should return the same curve instance on subsequent calls', () => {
      const curve1 = getSecp256K1Curve();
      const curve2 = getSecp256K1Curve();
      expect(curve1).toBeInstanceOf(EC);
      expect(curve1).toBe(curve2);
    });
  });

  describe('generatePrivateKey', () => {
    it('should generate a valid private key for the secp256k1 curve', () => {
      const privateKey = generatePrivateKey(ec);
      expect(BN.isBN(privateKey)).toBe(true);
      // private key should be less than the curve order
      expect(privateKey.lt(ec.n as BN)).toBe(true);
    });
  });

  describe('encryptedParamsBufToHex and encParamsHexToBuf', () => {
    const encParamsBuf: Ecies = {
      iv: Buffer.from('010203', 'hex'),
      ephemPublicKey: Buffer.from('04aabbcc', 'hex'),
      mac: Buffer.from('dead', 'hex'),
      ciphertext: Buffer.from('ciphertext'),
    };

    const encParamsHex: Omit<EciesHex, 'ciphertext'> = {
      iv: '010203',
      ephemPublicKey: '04aabbcc',
      mac: 'dead',
      mode: 'AES256',
    };

    it('encryptedParamsBufToHex should convert buffers to hex strings', () => {
      const result = encryptedParamsBufToHex(encParamsBuf);
      expect(result).toStrictEqual(encParamsHex);
    });

    it('encParamsHexToBuf should convert hex strings to buffers', () => {
      const { iv, ephemPublicKey, mac } = encParamsHexToBuf(encParamsHex);

      expect(Buffer.from(iv).equals(encParamsBuf.iv)).toBe(true);
      expect(
        Buffer.from(ephemPublicKey).equals(encParamsBuf.ephemPublicKey),
      ).toBe(true);
      expect(Buffer.from(mac).equals(encParamsBuf.mac)).toBe(true);
    });
  });

  describe('toChecksumAddress', () => {
    it('should be able to convert to EIP-55 `checksum` address', function () {
      const address = toChecksumAddress(
        '0x2e7be13cedb3ff3b413a6a468c0e63db6ed19864',
      );
      expect(address).toBe('0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864');
    });

    it('should handle addresses without 0x prefix', () => {
      const address = toChecksumAddress(
        '2e7be13cedb3ff3b413a6a468c0e63db6ed19864',
      );
      expect(address).toBe('0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864');
    });

    it('should handle already checksum-med addresses', () => {
      const address = toChecksumAddress(
        '0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864',
      );
      expect(address).toBe('0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864');
    });

    it('should handle uppercase input', () => {
      const address = toChecksumAddress(
        '0X2E7BE13CEDB3FF3B413A6A468C0E63DB6ED19864',
      );
      expect(address).toBe('0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864');
    });
  });

  describe('derivePubKey', () => {
    it('should derive the correct public key from a private key', () => {
      const privateKey = new BN(
        'c8714913135551c875c49ead59061675a19176575a22f75f8a16d8f8598f6734',
        'hex',
      );
      const expectedPubKeyPoint = ec
        .keyFromPrivate(privateKey.toString('hex'))
        .getPublic();
      const expectedPubKeyHex = expectedPubKeyPoint.encode('hex', false);

      const derivedPubKey = derivePubKey(ec, privateKey);
      const derivedPubKeyHex = derivedPubKey.encode('hex', false); // false for uncompressed
      expect(derivedPubKeyHex).toBe(expectedPubKeyHex);
    });
  });

  describe('uint8ArrayToHex', () => {
    it('should convert a Uint8Array to a hex string', () => {
      const arr = new Uint8Array([0, 1, 10, 15, 16, 255]);
      const expectedHex = '00010a0f10ff';
      expect(uint8ArrayToHex(arr)).toBe(expectedHex);
    });

    it('should handle empty Uint8Array', () => {
      const arr = new Uint8Array([]);
      expect(uint8ArrayToHex(arr)).toBe('');
    });
  });
});
