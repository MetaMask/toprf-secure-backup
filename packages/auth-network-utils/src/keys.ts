import { bs58 } from "@toruslabs/bs58";
import { INodePub, KEY_TYPE } from "@toruslabs/constants";
import { Ecies, encrypt } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import { sha512 } from "ethereum-cryptography/sha512";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { EncryptedSeed, ImportedShare, KeyType, MetadataOperation, NonceMetadataParams, PrivateKeyData, SetNonceData } from "./interfaces";
import Share from "./share";
import { encryptedParamsBufToHex, keccak256AndHexify } from "./common";
import { getRandomNonce } from "./internal";
import { generateRandomPolynomial } from "./lagrangeInterpolation";

// cache the curves locally to avoid re-initializing them on every call
let secp256k1EC: EC;
let ed25519EC: EC;

function stripHexPrefix(str: string): string {
  return str.startsWith("0x") ? str.slice(2) : str;
}

export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();

  const buf = Buffer.from(address, "utf8");
  const hash = keccak256AndHexify(buf).slice(2); // hash and remove 0x prefix

  let ret = "0x";
  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase();
    } else {
      ret += address[i];
    }
  }

  return ret;
}

function generateAddressFromEcKey(keyType: KeyType, key: EC.KeyPair): string {
  if (keyType === KEY_TYPE.SECP256K1) {
    const publicKey = key.getPublic().encode("hex", false).slice(2);
    const evmAddressLower = `0x${keccak256AndHexify(Buffer.from(publicKey, "hex")).slice(64 - 38)}`;
    return toChecksumAddress(evmAddressLower);
  } else if (keyType === KEY_TYPE.ED25519) {
    const publicKey = encodeEd25519Point(key.getPublic());
    const address = bs58.encode(publicKey);
    return address;
  }
  throw new Error(`Invalid keyType: ${keyType}`);
}

function adjustScalarBytes(bytes: Buffer): Buffer {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

// format ImportedShareData from share and key data
function parseImportedShare(params: {
  keyData: PrivateKeyData;
  share: Share;
  encryptedShare: Ecies;
  keyType: KeyType;
  nonceParams: NonceMetadataParams;
}): ImportedShare {
  const { keyData, share, encryptedShare, keyType, nonceParams } = params;
  const { oAuthKeyScalar: oAuthKey } = keyData;
  const ecCurve = getKeyCurve(keyType);
  const shareJson = share.toJSON() as Record<string, string>;
  const encParamsMetadata = encryptedParamsBufToHex(encryptedShare);
  const oAuthPubKey = ecCurve.keyFromPrivate(oAuthKey.toString("hex", 64), "hex").getPublic();

  const stringifiedSetData = stringify(nonceParams.set_data);
  if (!stringifiedSetData) {
    throw new Error("Set data is not set");
  }
  const nonceData = Buffer.from(stringifiedSetData, "utf8").toString("base64");

  const shareData: ImportedShare = {
    encrypted_seed: keyData.encryptedSeed,
    final_user_point: keyData.finalUserPubKeyPoint,
    oauth_pub_key_x: oAuthPubKey.getX().toString("hex"),
    oauth_pub_key_y: oAuthPubKey.getY().toString("hex"),
    signing_pub_key_x: keyData.SigningPubX.toString("hex"),
    signing_pub_key_y: keyData.SigningPubY.toString("hex"),
    encrypted_share: encParamsMetadata.ciphertext,
    encrypted_share_metadata: encParamsMetadata,
    node_index: Number.parseInt(shareJson.shareIndex, 16),
    key_type: keyType,
    nonce_data: nonceData,
    nonce_signature: nonceParams.signature,
  };

  return shareData;
}

export function getSecpKeyFromEd25519(ed25519Scalar: BN): {
  scalar: BN;
  point: curve.base.BasePoint;
} {
  const secp256k1Curve = getKeyCurve(KEY_TYPE.SECP256K1);
  if (!secp256k1Curve.n) {
    throw new Error("Curve is not set");
  }

  const ed25519KeyHex = ed25519Scalar.toString("hex", 64);
  const keyHash = keccak256AndHexify(Buffer.from(ed25519KeyHex, "hex"));
  const keyHashBn = new BN(keyHash.slice(2), "hex");

  const secpKey = keyHashBn.umod(secp256k1Curve.n).toString("hex", 64);
  const bufferKey = Buffer.from(secpKey, "hex");
  if (bufferKey.length !== 32) {
    throw new Error(`Key length must be equal to 32. got ${bufferKey.length}`);
  }

  const secpKeyPair = secp256k1Curve.keyFromPrivate(bufferKey);

  return {
    scalar: secpKeyPair.getPrivate(),
    point: secpKeyPair.getPublic(),
  };
}

export function generateAddressFromPrivKey(keyType: KeyType, privateKey: BN): string {
  const ecCurve = getKeyCurve(keyType);
  const key = ecCurve.keyFromPrivate(privateKey.toString("hex", 64), "hex");
  return generateAddressFromEcKey(keyType, key);
}

export function generateAddressFromPubKey(keyType: KeyType, publicKeyX: BN, publicKeyY: BN): string {
  const ecCurve = getKeyCurve(keyType);
  const key = ecCurve.keyFromPublic({ x: publicKeyX.toString("hex", 64), y: publicKeyY.toString("hex", 64) });
  return generateAddressFromEcKey(keyType, key);
}

/**
 * Generates and derives key data for a given key type and key buffer.
 * @param keyType - The type of key to use for the shares.
 * @param keyBuffer - Base data to derive the key data from.
 * @returns The key data.
 */
export async function generateKeyData(keyType: KeyType, keyBuffer: Buffer): Promise<PrivateKeyData> {
  const ecCurve = getKeyCurve(keyType);
  if (!ecCurve.n) {
    throw new Error("Curve is not set");
  }

  const metadataNonce = getRandomNonce(ecCurve);
  let encryptedSeed: string = "";
  let scalar: BN = new BN(keyBuffer);
  let finalUserPubKeyPoint = ecCurve.keyFromPrivate(scalar.toString("hex", 64), "hex").getPublic();

  if (keyType === KEY_TYPE.ED25519) {
    const finalEd25519Key = getEd25519ExtendedPublicKey(keyBuffer);
    const encryptionKey = getSecpKeyFromEd25519(finalEd25519Key.scalar);
    const encryptedSeedBuffer = await encrypt(Buffer.from(encryptionKey.point.encodeCompressed("hex"), "hex"), keyBuffer);
    const encData: EncryptedSeed = {
      enc_text: encryptedSeedBuffer.ciphertext.toString("hex"),
      metadata: encryptedParamsBufToHex(encryptedSeedBuffer),
      public_key: encodeEd25519Point(finalEd25519Key.point).toString("hex"),
    };

    scalar = finalEd25519Key.scalar;
    encryptedSeed = Buffer.from(JSON.stringify(encData), "utf-8").toString("base64");
    finalUserPubKeyPoint = finalEd25519Key.point;
  }

  const oauthKey = scalar.sub(metadataNonce).umod(ecCurve.n);
  const oAuthKeyPair = ecCurve.keyFromPrivate(oauthKey.toArrayLike(Buffer));

  let metadataSigningKey: BN = oAuthKeyPair.getPrivate();
  let SigningPubX: BN = oAuthKeyPair.getPublic().getX();
  let SigningPubY: BN = oAuthKeyPair.getPublic().getY();
  if (keyType === KEY_TYPE.ED25519) {
    const { scalar: secpScalar, point } = getSecpKeyFromEd25519(oAuthKeyPair.getPrivate());
    metadataSigningKey = secpScalar;
    SigningPubX = point.getX();
    SigningPubY = point.getY();
  }

  return {
    oAuthKeyScalar: oAuthKeyPair.getPrivate(),
    oAuthPubX: oAuthKeyPair.getPublic().getX(),
    oAuthPubY: oAuthKeyPair.getPublic().getY(),
    SigningPubX,
    SigningPubY,
    metadataNonce,
    metadataSigningKey,
    encryptedSeed,
    finalUserPubKeyPoint,
  };
}

export function getPostboxKeyFrom1OutOf1(ecCurve: EC, privKey: string, nonce: string): string {
  if (!ecCurve.n) {
    throw new Error("Curve is not set");
  }

  const privKeyBN = new BN(privKey, 16);
  const nonceBN = new BN(nonce, 16);
  return privKeyBN.sub(nonceBN).umod(ecCurve.n).toString("hex");
}

export function derivePubKey(ecCurve: EC, sk: BN): curve.base.BasePoint {
  const skHex = sk.toString(16, 64);
  return ecCurve.keyFromPrivate(skHex, "hex").getPublic();
}

export function getKeyCurve(keyType: KeyType = KEY_TYPE.SECP256K1) {
  if (keyType === KEY_TYPE.SECP256K1) {
    if (!secp256k1EC) {
      secp256k1EC = new EC("secp256k1");
    }
    return secp256k1EC;
  } else if (keyType === KEY_TYPE.ED25519) {
    if (!ed25519EC) {
      ed25519EC = new EC("ed25519");
    }
    return ed25519EC;
  }
  throw new Error(`Unsupported key type: ${keyType}`);
}

/** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
export function getEd25519ExtendedPublicKey(keyBuffer: Buffer): {
  scalar: BN;
  point: curve.base.BasePoint;
} {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);
  const len = 32;
  const G = ed25519Curve.g;
  const N = ed25519Curve.n;
  if (!N) {
    throw new Error("`n` is not set in curve");
  }

  if (keyBuffer.length !== len) {
    log.error("Invalid seed for ed25519 key derivation", keyBuffer.length);
    throw new Error("Invalid seed for ed25519 key derivation");
  }
  // Hash private key with curve's hash function to produce uniformingly random input
  // Check byte lengths: ensure(64, h(ensure(32, key)))
  const hashed = sha512(keyBuffer);
  if (hashed.length !== 64) {
    throw new Error("Invalid hash length for ed25519 seed");
  }
  const head = new BN(adjustScalarBytes(Buffer.from(hashed.slice(0, len))), "le");
  const scalar = new BN(head.umod(N), "le"); // The actual private scalar
  const point = G.mul(scalar) as curve.base.BasePoint; // Point on Edwards curve aka public key
  return { scalar, point };
}

export function encodeEd25519Point(point: curve.base.BasePoint) {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);
  if (!ed25519Curve.n) {
    throw new Error("`n` is not set in curve");
  }

  const encodingLength = Math.ceil(ed25519Curve.n.bitLength() / 8);
  const enc = point.getY().toArrayLike(Buffer, "le", encodingLength);
  enc[encodingLength - 1] |= point.getX().isOdd() ? 0x80 : 0;
  return enc;
}

/**
 * Generates nonce metadata parameters for a given server time offset, operation, private key, key type, nonce, and seed.
 * @param serverTimeOffset - The server time offset.
 * @param operation - The operation to perform.
 * @param privateKey - The private key to generate the metadata signature.
 * @param keyType - The type of key to use for the meatadata.
 * @param nonce - The nonce to use for the meatadata operation.
 * @param seed - The seed to use for the nonce.
 * @returns The nonce metadata parameters.
 */
export function generateNonceMetadataParams(
  serverTimeOffset: number,
  operation: MetadataOperation,
  privateKey: BN,
  keyType: KeyType,
  nonce?: BN,
  seed?: string
): NonceMetadataParams {
  // metadata only uses secp for sig validation
  const key = getKeyCurve(KEY_TYPE.SECP256K1).keyFromPrivate(privateKey.toString("hex", 64), "hex");
  const setData: Partial<SetNonceData> = {
    operation,
    timestamp: new BN(~~(serverTimeOffset + Date.now() / 1000)).toString(16),
  };

  if (nonce) {
    setData.data = nonce.toString("hex", 64);
  }

  if (seed) {
    setData.seed = seed;
  } else {
    setData.seed = ""; // setting it as empty to keep ordering same while serializing the data on backend.
  }

  const stringifiedSetData = stringify(setData);
  if (!stringifiedSetData) {
    throw new Error("Set data is not set");
  }

  const sig = key.sign(keccak256AndHexify(Buffer.from(stringifiedSetData, "utf8")).slice(2));
  return {
    pub_key_X: key.getPublic().getX().toString("hex", 64),
    pub_key_Y: key.getPublic().getY().toString("hex", 64),
    set_data: setData,
    key_type: keyType,
    signature: Buffer.from(sig.r.toString(16, 64) + sig.s.toString(16, 64) + new BN("").toString(16, 2), "hex").toString("base64"),
  };
}

/**
 * Generates secret shares for a given set of node indexes and public keys\
 * and formats them to ImportedShareData to be used to make `ImportShareRequest`
 *
 * @param keyType - The type of key to use for the shares.
 * @param serverTimeOffset - The server time offset.
 * @param nodeIndexes - The node indexes to generate shares for.
 * @param nodePubkeys - The public keys for the nodes.
 * @param secret - The secret to be splited into shares.
 **/
export async function generateShares(
  keyType: KeyType,
  serverTimeOffset: number,
  nodeIndexes: BN[],
  nodePubkeys: INodePub[],
  secret: Buffer
): Promise<ImportedShare[]> {
  const ecCurve = getKeyCurve(keyType);
  // generate key data
  const keyData = await generateKeyData(keyType, secret);
  const { metadataNonce, oAuthKeyScalar: oAuthKey, encryptedSeed, metadataSigningKey } = keyData;
  const threshold = ~~(nodePubkeys.length / 2) + 1;
  const degree = threshold - 1;

  // generate random polynomial based on oAuthKey
  const poly = generateRandomPolynomial(ecCurve, degree, oAuthKey);
  // generate shares from polynomial
  const shares = poly.generateShares(nodeIndexes);
  // generate nonce params
  const nonceParams = generateNonceMetadataParams(serverTimeOffset, "getOrSetNonce", metadataSigningKey, keyType, metadataNonce, encryptedSeed);

  // encrypt shares
  const encryptedShares = await Promise.all(
    nodeIndexes.map((nodeIdxBn, index) => {
      const shareJson = shares[nodeIdxBn.toString("hex", 64)].toJSON() as Record<string, string>;

      const nodePubKeyPoint = nodePubkeys[index];
      if (!nodePubKeyPoint) {
        throw new Error(`Missing node pub key for node index: ${nodeIdxBn.toString("hex", 64)}`);
      }
      const nodePubKey = getKeyCurve().keyFromPublic({ x: nodePubKeyPoint.X, y: nodePubKeyPoint.Y });
      return encrypt(Buffer.from(nodePubKey.getPublic().encodeCompressed("hex"), "hex"), Buffer.from(shareJson.share.padStart(64, "0"), "hex"));
    })
  );

  // format/parse encrypted shares to ImportedShareData
  const sharesData: ImportedShare[] = nodeIndexes.map((nodeIndexBn, index) => {
    const encryptedShare = encryptedShares[index];
    const nodeIndexStr = nodeIndexBn.toString("hex", 64);
    return parseImportedShare({ keyData, share: shares[nodeIndexStr], encryptedShare, keyType, nonceParams });
  });

  return sharesData;
}
