import BN from 'bn.js';
import type { curve } from 'elliptic';
import { ec as EC } from 'elliptic';
import type { Ecies } from '@toruslabs/eccrypto';
import type {
  EciesHex,
} from './interfaces';
import { keccak256AndHexify } from './common';

// generate a 32 bytes private key buffer
/**
 *
 * @param ecCurve
 */
export function generate32BytesPrivateKeyBuffer(ecCurve: EC): Buffer {
  const privateKey = ecCurve.genKeyPair().getPrivate();
  const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
  return privateKeyBuffer;
}


/**
 *
 * @param encParams
 */
export function encryptedParamsBufToHex(encParams: Ecies): EciesHex {
  return {
    iv: Buffer.from(encParams.iv).toString('hex'),
    ephemPublicKey: Buffer.from(encParams.ephemPublicKey).toString('hex'),
    ciphertext: Buffer.from(encParams.ciphertext).toString('hex'),
    mac: Buffer.from(encParams.mac).toString('hex'),
    mode: 'AES256',
  };
}

/**
 *
 * @param eciesData
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
 *
 * @param str
 */
function stripHexPrefix(str: string): string {
  return str.startsWith('0x') ? str.slice(2) : str;
}

/**
 *
 * @param hexAddress
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
 *
 * @param ecCurve
 * @param sk
 */
export function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint {
  const skHex = sk.toString(16, 64);
  return ecCurve.keyFromPrivate(skHex, 'hex').getPublic();
}



