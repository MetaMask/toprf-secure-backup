"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pubKeyToSec1 = exports.derivePubKey = exports.toChecksumAddress = exports.encParamsHexToBuf = exports.encryptedParamsBufToHex = exports.generate32BytesPrivateKeyBuffer = exports.getSecp256K1Curve = void 0;
const elliptic_1 = require("elliptic");
const common_1 = require("./common.cjs");
let secp256k1Curve = null;
/**
 * Instantiate the secp256k1 elliptic curve instance if it doesn't exist
 *
 * @returns secp256k1 elliptic curve
 */
function getSecp256K1Curve() {
    secp256k1Curve = secp256k1Curve ?? new elliptic_1.ec('secp256k1');
    return secp256k1Curve;
}
exports.getSecp256K1Curve = getSecp256K1Curve;
// generate a 32 bytes private key buffer
/**
 * Generates a 32 bytes private key buffer
 *
 * @param ecCurve - The elliptic curve to use
 * @returns The 32 bytes private key buffer
 */
function generate32BytesPrivateKeyBuffer(ecCurve) {
    const privateKey = ecCurve.genKeyPair().getPrivate();
    const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
    return privateKeyBuffer;
}
exports.generate32BytesPrivateKeyBuffer = generate32BytesPrivateKeyBuffer;
/**
 * Converts an encrypted parameters buffer to a hex string
 *
 * @param encParams - The encrypted parameters with fields as buffers
 * @returns The encrypted parameters with fields converted to hex strings
 */
function encryptedParamsBufToHex(encParams) {
    return {
        iv: Buffer.from(encParams.iv).toString('hex'),
        ephemPublicKey: Buffer.from(encParams.ephemPublicKey).toString('hex'),
        mac: Buffer.from(encParams.mac).toString('hex'),
        mode: 'AES256',
    };
}
exports.encryptedParamsBufToHex = encryptedParamsBufToHex;
/**
 * Converts an encrypted parameters hex string to a buffer
 *
 * @param eciesData - The encrypted parameters with fields as hex strings
 * @returns The encrypted parameters with fields converted to buffers
 */
function encParamsHexToBuf(eciesData) {
    return {
        ephemPublicKey: Buffer.from(eciesData.ephemPublicKey, 'hex'),
        iv: Buffer.from(eciesData.iv, 'hex'),
        mac: Buffer.from(eciesData.mac, 'hex'),
    };
}
exports.encParamsHexToBuf = encParamsHexToBuf;
/**
 * Strips the hex prefix from a string
 *
 * @param str - The string to strip the hex prefix from
 * @returns The string without the hex prefix
 */
function stripHexPrefix(str) {
    return str.startsWith('0x') ? str.slice(2) : str;
}
/**
 * Converts an address to a checksum address
 *
 * @param hexAddress - The address to convert to a checksum address
 * @returns The checksum address
 */
function toChecksumAddress(hexAddress) {
    const address = stripHexPrefix(hexAddress).toLowerCase();
    const buf = Buffer.from(address, 'utf8');
    const hash = (0, common_1.keccak256AndHexify)(buf).slice(2); // hash and remove 0x prefix
    let ret = '0x';
    for (let i = 0; i < address.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            ret += address[i].toUpperCase();
        }
        else {
            ret += address[i];
        }
    }
    return ret;
}
exports.toChecksumAddress = toChecksumAddress;
/**
 * Derives a public key from a private key
 *
 * @param ecCurve - The elliptic curve to use
 * @param sk - The private key
 * @returns The public key
 */
function derivePubKey(ecCurve, sk) {
    const skHex = sk.toString(16, 64);
    return ecCurve.keyFromPrivate(skHex, 'hex').getPublic();
}
exports.derivePubKey = derivePubKey;
/**
 * Converts a Uint8Array public key to SEC1 encoded format
 * Format: 0x04 || x || y where x and y are 32-byte coordinates
 *
 * @param pubKey - Uint8Array public key to convert
 * @returns SEC1 encoded public key string
 */
const pubKeyToSec1 = (pubKey) => {
    // SEC1 uncompressed format starts with 0x04
    // Then has X and Y coordinates (32 bytes each)
    const prefix = '04';
    // Convert Uint8Array to hex string
    const pubKeyHex = Array.from(pubKey)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    if (pubKeyHex.startsWith('04')) {
        return pubKeyHex;
    }
    return prefix + pubKeyHex;
};
exports.pubKeyToSec1 = pubKeyToSec1;
//# sourceMappingURL=cryptoUtils.cjs.map