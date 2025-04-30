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
  secp256k1Curve = secp256k1Curve ?? new EC('secp256k1');
  return secp256k1Curve;
}

/**
 * Generates a private key for the given curve.
 *
 * @param ecCurve - The elliptic curve to use
 * @returns The private key
 */
export function generatePrivateKey(ecCurve: EC): BN {
  const privateKey = ecCurve.genKeyPair().getPrivate();
  return privateKey;
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
    iv: Buffer.from(eciesData.iv, 'hex'),
    ephemPublicKey: Buffer.from(eciesData.ephemPublicKey, 'hex'),
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
  if (str.startsWith('0x') || str.startsWith('0X')) {
    return str.slice(2);
  }
  return str;
}

/**
 * Converts an address to a checksum address
 *
 * @param hexAddress - The address to convert to a checksum address
 * @returns The checksum address
 */
export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();

  const buffer = Buffer.from(address, 'utf8');
  const hash = keccak256AndHexify(buffer).slice(2); // hash and remove 0x prefix

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

/**
 * Converts a Uint8Array to a hex string
 *
 * @param uint8Array - The Uint8Array to convert
 * @returns Hexadecimal string representation
 */
export function uint8ArrayToHex(uint8Array: Uint8Array): string {
  return Array.from(uint8Array)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}
