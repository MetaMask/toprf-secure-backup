import { bs58 } from '@toruslabs/bs58';
import { KEY_TYPE } from '@toruslabs/constants';
import BN from 'bn.js';
import stringify from 'json-stable-stringify';

import { generate32BytesPrivateKeyBuffer } from './common';
import {
  generateAddressFromPrivKey,
  generateKeyData,
  generateNonceMetadataParams,
  generateShares,
  getEd25519ExtendedPublicKey,
  getKeyCurve,
  getSecpKeyFromEd25519,
  toChecksumAddress,
} from './keys';
import { NODE_DETAILS } from '../tests/testConfig';

describe('keys utils', function () {
  it('should be able to convert to EIP-55 `checksum` address', function () {
    const address = toChecksumAddress(
      '0x2e7be13cedb3ff3b413a6a468c0e63db6ed19864',
    );
    expect(address).toBe('0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864');
  });

  it('should be able to generate addresses for secp256k1', function () {
    const testPrivateKey = new BN(
      'ca31f594168b9920ce99e7d5c43a4c4f9f2c13b29d35073c7551521f3c48beb7',
      'hex',
    );
    const ethereumAddress = generateAddressFromPrivKey(
      KEY_TYPE.SECP256K1,
      testPrivateKey,
    );

    expect(ethereumAddress).toHaveLength(42);
    expect(ethereumAddress.toLowerCase()).toBe(
      '0x2e7be13cedb3ff3b413a6a468c0e63db6ed19864',
    );
  });

  it('should be able to generate addresses for ed25519', function () {
    const keyType = KEY_TYPE.ED25519;
    const ecCurve = getKeyCurve(keyType);
    const privateKey = ecCurve.genKeyPair().getPrivate();

    const ed25519Address = generateAddressFromPrivKey(keyType, privateKey);
    // ed25519 address is base58 encoded and the original value before encoding is 32 bytes (public key)
    const decodedAddress = bs58.decode(ed25519Address);
    expect(decodedAddress).toHaveLength(32);
  });

  it('should be able to generate key data for secp256k1', async function () {
    const internalUtils = await import('./internal.js');

    const keyType = KEY_TYPE.SECP256K1;
    const privateKeyBuffer = generate32BytesPrivateKeyBuffer(
      getKeyCurve(keyType),
    );
    const curve = getKeyCurve(keyType);
    const mockMetadataNonce = new BN(generate32BytesPrivateKeyBuffer(curve));
    const getMetadataNonceSpy = jest
      .spyOn(internalUtils, 'getRandomNonce')
      .mockReturnValue(mockMetadataNonce);
    const scalar: BN = new BN(privateKeyBuffer);
    const oauthKey = scalar.sub(mockMetadataNonce).umod(curve.n!);
    const oAuthKeyPair = curve.keyFromPrivate(oauthKey.toArrayLike(Buffer));

    const keyData = await generateKeyData(keyType, privateKeyBuffer);

    const expectedMetadataSigningKey = oAuthKeyPair.getPrivate();
    const expectedSigningPubX = oAuthKeyPair.getPublic().getX();
    const expectedSigningPubY = oAuthKeyPair.getPublic().getY();
    const expectedFinalUserPubKeyPoint = curve
      .keyFromPrivate(scalar.toString('hex', 64), 'hex')
      .getPublic();

    expect(keyData).not.toBeNull();
    expect(getMetadataNonceSpy).toHaveBeenCalled();
    expect(keyData.encryptedSeed).toBe('');
    expect(keyData.metadataSigningKey.eq(expectedMetadataSigningKey)).toBe(
      true,
    );
    expect(keyData.finalUserPubKeyPoint.eq(expectedFinalUserPubKeyPoint)).toBe(
      true,
    );
    expect(keyData.SigningPubX.eq(expectedSigningPubX)).toBe(true);
    expect(keyData.SigningPubY.eq(expectedSigningPubY)).toBe(true);
  });

  it('should be able to generate key data for ed25519', async function () {
    const internalUtils = await import('./internal.js');

    const keyType = KEY_TYPE.ED25519;
    const privateKeyBuffer = generate32BytesPrivateKeyBuffer(
      getKeyCurve(keyType),
    );
    const finalEd25519Key = getEd25519ExtendedPublicKey(privateKeyBuffer);
    const { scalar } = finalEd25519Key;
    const curve = getKeyCurve(keyType);
    const mockMetadataNonce = new BN(generate32BytesPrivateKeyBuffer(curve));
    const getMetadataNonceSpy = jest
      .spyOn(internalUtils, 'getRandomNonce')
      .mockReturnValue(mockMetadataNonce);
    const oAuthKey = scalar.sub(mockMetadataNonce).umod(curve.n!);
    const oAuthKeyPair = curve.keyFromPrivate(oAuthKey.toArrayLike(Buffer));

    const keyData = await generateKeyData(keyType, privateKeyBuffer);

    const { scalar: expectedMetadataSigningKey, point } = getSecpKeyFromEd25519(
      oAuthKeyPair.getPrivate(),
    );
    const expectedSigningPubX = point.getX();
    const expectedSigningPubY = point.getY();
    const expectedFinalUserPubKeyPoint = finalEd25519Key.point;

    expect(keyData).not.toBeNull();
    expect(getMetadataNonceSpy).toHaveBeenCalled();
    expect(keyData.encryptedSeed).not.toBe('');
    expect(mockMetadataNonce.eq(keyData.metadataNonce)).toBe(true);
    expect(expectedMetadataSigningKey.eq(keyData.metadataSigningKey)).toBe(
      true,
    );
    expect(expectedSigningPubX.eq(keyData.SigningPubX)).toBe(true);
    expect(expectedSigningPubY.eq(keyData.SigningPubY)).toBe(true);
    expect(expectedFinalUserPubKeyPoint.eq(keyData.finalUserPubKeyPoint)).toBe(
      true,
    );
  });

  it('should be able to generate shares', async function () {
    const internalUtils = await import('./internal.js');
    const keyType = KEY_TYPE.SECP256K1;
    const curve = getKeyCurve(keyType);

    const mockMetadataNonce = new BN(generate32BytesPrivateKeyBuffer(curve));
    const getMetadataNonceSpy = jest
      .spyOn(internalUtils, 'getRandomNonce')
      .mockReturnValue(mockMetadataNonce);

    const serverTimeOffset = 0;
    const privateKeyBuffer = Buffer.from(
      'f8135fdccecce1e1da2253335e3fbef307bee49a104ed25eaa5122c46f9994a8',
      'hex',
    );

    const nodeIndexes = NODE_DETAILS.torusIndexes.map(
      (nodeIdx) => new BN(nodeIdx),
    );
    const nodePubkeys = NODE_DETAILS.torusNodePub;
    const scalar: BN = new BN(privateKeyBuffer);
    const oauthKey = scalar.sub(mockMetadataNonce).umod(curve.n!);
    const oAuthKeyPair = curve.keyFromPrivate(oauthKey.toArrayLike(Buffer));
    const metadataSigningKey = oAuthKeyPair.getPrivate();
    const nonceParams = generateNonceMetadataParams(
      serverTimeOffset,
      'getOrSetNonce',
      metadataSigningKey,
      keyType,
      mockMetadataNonce,
      '',
    );

    const expectedNonceSig = nonceParams.signature;
    const expectedNonceData = Buffer.from(
      stringify(nonceParams.set_data)!,
      'utf8',
    ).toString('base64');
    const expectedSigningPubX = oAuthKeyPair.getPublic().getX().toString('hex');
    const expectedSigningPubY = oAuthKeyPair.getPublic().getY().toString('hex');

    const shares = await generateShares(
      keyType,
      serverTimeOffset,
      nodeIndexes,
      nodePubkeys,
      privateKeyBuffer,
    );

    expect(shares).toHaveLength(nodeIndexes.length);
    expect(getMetadataNonceSpy).toHaveBeenCalled();
    const isValidNonceSig = shares.every(
      (share) => share.nonce_signature === expectedNonceSig,
    );
    expect(isValidNonceSig).toBe(true);
    const isValidNonceData = shares.every(
      (share) => share.nonce_data === expectedNonceData,
    );
    expect(isValidNonceData).toBe(true);
    const isValidSigningPubX = shares.every(
      (share) => share.signing_pub_key_x === expectedSigningPubX,
    );
    expect(isValidSigningPubX).toBe(true);
    const isValidSigningPubY = shares.every(
      (share) => share.signing_pub_key_y === expectedSigningPubY,
    );
    expect(isValidSigningPubY).toBe(true);
  });

  it('should be able to generate shares for ed25519', async function () {
    const internalUtils = await import('./internal.js');
    const keyType = KEY_TYPE.ED25519;
    const curve = getKeyCurve(keyType);

    const mockMetadataNonce = new BN(generate32BytesPrivateKeyBuffer(curve));
    const getMetadataNonceSpy = jest
      .spyOn(internalUtils, 'getRandomNonce')
      .mockReturnValue(mockMetadataNonce);

    const serverTimeOffset = 0;
    const privateKeyBuffer = generate32BytesPrivateKeyBuffer(curve);
    const nodeIndexes = NODE_DETAILS.torusIndexes.map(
      (nodeIdx) => new BN(nodeIdx),
    );
    const nodePubkeys = NODE_DETAILS.torusNodePub;

    const shares = await generateShares(
      keyType,
      serverTimeOffset,
      nodeIndexes,
      nodePubkeys,
      privateKeyBuffer,
    );
    expect(shares).toHaveLength(nodeIndexes.length);
    expect(getMetadataNonceSpy).toHaveBeenCalled();
  });
});
