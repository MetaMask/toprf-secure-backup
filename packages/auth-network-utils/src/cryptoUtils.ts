import type { Ecies } from '@toruslabs/eccrypto';
import type BN from 'bn.js';
import type { curve } from 'elliptic';
import { ec as EC } from 'elliptic';

import { keccak256AndHexify } from './common';
import type { EciesHex } from './interfaces';

let secp256k1Curve: EC | null = null;

/**
 * Instantiate the secp256k1 elliptic curve instance if it doesn't exist
 *
 * @returns secp256k1 elliptic curve
 */
export function getSecp256K1Curve(): EC {
  if (!secp256k1Curve) {
    secp256k1Curve = new EC('secp256k1');
  }
  return secp256k1Curve;
}

// generate a 32 bytes private key buffer
/**
 * Generates a 32 bytes private key buffer
 *
 * @param ecCurve - The elliptic curve to use
 * @returns The 32 bytes private key buffer
 */
export function generate32BytesPrivateKeyBuffer(ecCurve: EC): Buffer {
  const privateKey = ecCurve.genKeyPair().getPrivate();
  const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
  return privateKeyBuffer;
}

/**
 * Converts an encrypted parameters buffer to a hex string
 *
 * @param encParams - The encrypted parameters with fields as buffers
 * @returns The encrypted parameters with fields converted to hex strings
 */
export function encryptedParamsBufToHex(
  encParams: Ecies,
): Omit<EciesHex, 'ciphertext'> {
  return {
    iv: Buffer.from(encParams.iv).toString('hex'),
    ephemPublicKey: Buffer.from(encParams.ephemPublicKey).toString('hex'),
    mac: Buffer.from(encParams.mac).toString('hex'),
    mode: 'AES256',
  };
}

/**
 * Converts an encrypted parameters hex string to a buffer
 *
 * @param eciesData - The encrypted parameters with fields as hex strings
 * @returns The encrypted parameters with fields converted to buffers
 */
export function encParamsHexToBuf(
  eciesData: Omit<EciesHex, 'ciphertext'>,
): Omit<Ecies, 'ciphertext'> {
  return {
    ephemPublicKey: Buffer.from(eciesData.ephemPublicKey, 'hex'),
    iv: Buffer.from(eciesData.iv, 'hex'),
    mac: Buffer.from(eciesData.mac, 'hex'),
  };
}

/**
 * Strips the hex prefix from a string
 *
 * @param str - The string to strip the hex prefix from
 * @returns The string without the hex prefix
 */
function stripHexPrefix(str: string): string {
  return str.startsWith('0x') ? str.slice(2) : str;
}

/**
 * Converts an address to a checksum address
 *
 * @param hexAddress - The address to convert to a checksum address
 * @returns The checksum address
 */
export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();

  const buf = Buffer.from(address, 'utf8');
  const hash = keccak256AndHexify(buf).slice(2); // hash and remove 0x prefix

  let ret = '0x';
  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase();
    } else {
      ret += address[i];
    }
  }

  return ret;
}

/**
 * Derives a public key from a private key
 *
 * @param ecCurve - The elliptic curve to use
 * @param sk - The private key
 * @returns The public key
 */
export function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint {
  const skHex = sk.toString(16, 64);
  return ecCurve.keyFromPrivate(skHex, 'hex').getPublic();
}
