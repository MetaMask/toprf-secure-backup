/// <reference types="node" />
/// <reference types="node" />
import type { Ecies } from "@toruslabs/eccrypto";
import type BN from "bn.js";
import type { curve } from "elliptic";
import { ec as EC } from "elliptic";
import type { EciesHex } from "./interfaces.cjs";
/**
 * Instantiate the secp256k1 elliptic curve instance if it doesn't exist
 *
 * @returns secp256k1 elliptic curve
 */
export declare function getSecp256K1Curve(): EC;
/**
 * Generates a 32 bytes private key buffer
 *
 * @param ecCurve - The elliptic curve to use
 * @returns The 32 bytes private key buffer
 */
export declare function generate32BytesPrivateKeyBuffer(ecCurve: EC): Buffer;
/**
 * Converts an encrypted parameters buffer to a hex string
 *
 * @param encParams - The encrypted parameters with fields as buffers
 * @returns The encrypted parameters with fields converted to hex strings
 */
export declare function encryptedParamsBufToHex(encParams: Ecies): Omit<EciesHex, 'ciphertext'>;
/**
 * Converts an encrypted parameters hex string to a buffer
 *
 * @param eciesData - The encrypted parameters with fields as hex strings
 * @returns The encrypted parameters with fields converted to buffers
 */
export declare function encParamsHexToBuf(eciesData: Omit<EciesHex, 'ciphertext'>): Omit<Ecies, 'ciphertext'>;
/**
 * Converts an address to a checksum address
 *
 * @param hexAddress - The address to convert to a checksum address
 * @returns The checksum address
 */
export declare function toChecksumAddress(hexAddress: string): string;
/**
 * Derives a public key from a private key
 *
 * @param ecCurve - The elliptic curve to use
 * @param sk - The private key
 * @returns The public key
 */
export declare function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint;
/**
 * Converts a Uint8Array public key to SEC1 encoded format
 * Format: 0x04 || x || y where x and y are 32-byte coordinates
 *
 * @param pubKey - Uint8Array public key to convert
 * @returns SEC1 encoded public key string
 */
export declare const pubKeyToSec1: (pubKey: Uint8Array) => string;
//# sourceMappingURL=cryptoUtils.d.cts.map