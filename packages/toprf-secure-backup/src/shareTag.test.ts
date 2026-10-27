import { encParamsHexToBuf } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { toBytes } from '@noble/hashes/utils';
import { decrypt } from '@toruslabs/eccrypto';
import BN from 'bn.js';

import { ShareTag } from './constants';
import { TOPRFErrorCode } from './errors';
import { getPubKey } from './getPubKeyRequest';
import * as getPubKeyModule from './getPubKeyRequest';
import type { KeyChangeProof, NodeAuthTokens } from './interfaces';
import { resetRateLimits } from './resetRateLimits';
import * as resetRateLimitsModule from './resetRateLimits';
import * as storeSharesRequestModule from './storeSharesRequest';
import {
  changeKeyShares,
  createKeyChangeRequestParams,
  createStoreKeySharesRequestParams,
  storeKeyShares,
} from './storeSharesRequest';
import * as toprfEvalRequestModule from './toprfEvalRequest';
import { recoverTOPRFSeed } from './toprfEvalRequest';
import { ToprfSecureBackup } from './toprfSecureBackup';
import * as utilsModule from './utils';

const nodeIndexes = [1, 2, 3, 4, 5];
const nodeAuthTokens: NodeAuthTokens = nodeIndexes.map((nodeIndex) => ({
  authToken: `token-${nodeIndex}`,
  nodeIndex,
  nodePubKey: 'pk',
}));
const nodeEndpointsMap: Record<number, string> = Object.fromEntries(
  nodeIndexes.map((nodeIndex) => [
    nodeIndex,
    `https://node-${nodeIndex}.example/sss/jrpc`,
  ]),
);

/**
 * Makes every outgoing JSON-RPC request resolve with the given result.
 *
 * @param result - The JSON-RPC `result` each node returns.
 * @returns The fetch spy, so the captured requests can be inspected.
 */
const mockJrpcFetch = (result: unknown): jest.SpyInstance => {
  // eslint-disable-next-line no-restricted-globals
  const headers = new Headers();
  headers.set('content-type', 'application/json');
  return jest.spyOn(global, 'fetch').mockImplementation(
    async () =>
      // eslint-disable-next-line no-restricted-globals
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        status: 200,
        headers,
      }),
  );
};

/**
 * Returns the `params` object sent in each captured JSON-RPC request.
 *
 * @param fetchSpy - The fetch spy returned by `mockJrpcFetch`.
 * @returns The parsed `params` of every captured request.
 */
const sentParams = (fetchSpy: jest.SpyInstance): Record<string, unknown>[] =>
  fetchSpy.mock.calls.map(
    ([, init]) => JSON.parse(init?.body as string).params,
  );

/**
 * Returns the `share_tag` value sent in each captured request.
 *
 * @param fetchSpy - The fetch spy returned by `mockJrpcFetch`.
 * @returns The `share_tag` of every captured request, undefined when absent.
 */
const sentShareTags = (fetchSpy: jest.SpyInstance): unknown[] =>
  sentParams(fetchSpy).map((params) => params.share_tag);

/**
 * Empty eval output is what a node returns when it has no share for the tag.
 */
const emptyEvalResult = {
  blindedOutputX: '',
  blindedOutputY: '',
  nodeIndex: 1,
  pubKey: '',
  keyShareIndex: 0,
  guessCount: 0,
  lockTimeSeconds: 0,
};

describe('share_tag on the wire', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('sends share_tag on get pub key requests when a tag is given', async () => {
    const fetchSpy = mockJrpcFetch({ pubKey: '04ab', keyIndex: 1 });

    await getPubKey({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      shareTag: ShareTag.RecoverySecret,
    });

    expect(sentShareTags(fetchSpy)).toStrictEqual(
      nodeAuthTokens.map(() => 'recovery_secret'),
    );
  });

  it('sends share_tag password on get pub key requests for the default share', async () => {
    const fetchSpy = mockJrpcFetch({ pubKey: '04ab', keyIndex: 1 });

    await getPubKey({
      shareTag: ShareTag.Password,
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
    });

    expect(sentShareTags(fetchSpy)).toStrictEqual(
      nodeAuthTokens.map(() => 'password'),
    );
  });

  it('rejects an empty pub key from a tagged miss', async () => {
    mockJrpcFetch({ pubKey: '', keyIndex: 0 });

    await expect(
      getPubKey({
        authTokens: nodeAuthTokens,
        nodeEndpointsMap,
        authConnectionId: 'conn',
        userId: 'user',
        shareTag: ShareTag.RecoverySecret,
      }),
    ).rejects.toThrow('Could not derive threshold auth pub key');
  });

  it('sends share_tag on reset rate limit requests when a tag is given', async () => {
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
      shareTag: ShareTag.RecoverySecret,
    });

    expect(sentShareTags(fetchSpy)).toStrictEqual(
      nodeAuthTokens.map(() => 'recovery_secret'),
    );
  });

  it('sends share_tag password on reset rate limit requests for the default share', async () => {
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      shareTag: ShareTag.Password,
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
    });

    expect(sentShareTags(fetchSpy)).toStrictEqual(
      nodeAuthTokens.map(() => 'password'),
    );
  });

  it.each([
    { label: 'with a tag', shareTag: ShareTag.RecoverySecret },
    { label: 'the default (Password) share', shareTag: ShareTag.Password },
  ])('eval requests for $label fail on a miss', async ({ shareTag }) => {
    // A node with no share returns an empty pubKey and empty outputs.
    // The threshold pub key check runs first, so the call fails with a TOPRF error.
    const fetchSpy = mockJrpcFetch(emptyEvalResult);

    const caught = await recoverTOPRFSeed({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      userInput: toBytes('password'),
      shareTag,
    }).catch((error: unknown) => error);

    expect(caught).toMatchObject({
      code: TOPRFErrorCode.CouldNotDeriveThresholdAuthPubKey,
    });
    expect(sentShareTags(fetchSpy)).toStrictEqual(
      nodeAuthTokens.map(() => shareTag),
    );
  });

  it('filters eval responses with empty blinded outputs instead of parsing them', async () => {
    // Valid pubKey, but empty blinded outputs: the empty outputs must be filtered out.
    mockJrpcFetch({ ...emptyEvalResult, pubKey: '04ab' });

    const caught = await recoverTOPRFSeed({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      userInput: toBytes('password'),
      shareTag: ShareTag.RecoverySecret,
    }).catch((error: unknown) => error);

    expect(caught).toMatchObject({
      code: TOPRFErrorCode.InsufficientValidResponses,
    });
  });

  it('sends share_tag at the top level of store key share requests', async () => {
    jest
      .spyOn(utilsModule, 'generateShareImportItems')
      .mockResolvedValue([] as never);
    const fetchSpy = mockJrpcFetch(null);

    await storeKeyShares({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      keyShareIndex: 1,
      oprfKey: 1n,
      authPubKey: new Uint8Array([4, 1, 2]),
      shareTag: ShareTag.RecoverySecret,
    });

    const [params] = sentParams(fetchSpy);
    expect(params.share_tag).toBe('recovery_secret');
    expect(params.share_import_items).toStrictEqual([]);
  });

  it('sends share_tag at the top level of change key share requests', async () => {
    jest
      .spyOn(utilsModule, 'generateShareImportItems')
      .mockResolvedValue([] as never);
    const fetchSpy = mockJrpcFetch(null);

    await changeKeyShares({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      keyShareIndex: 2,
      newOprfKey: 1n,
      newAuthPubKey: new Uint8Array([4, 1, 2]),
      oldAuthPrivKey: 1n,
      shareTag: ShareTag.RecoverySecret,
    });

    const [params] = sentParams(fetchSpy);
    expect(params.share_tag).toBe('recovery_secret');
    expect(params.share_import_items).toStrictEqual([]);
  });
});

describe('share_tag in signed payloads', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  /**
   * Returns the parsed `signed_data` of each captured reset rate limit request.
   *
   * @param fetchSpy - The fetch spy returned by `mockJrpcFetch`.
   * @returns The signed reset payloads.
   */
  const sentSignedData = (
    fetchSpy: jest.SpyInstance,
  ): Record<string, unknown>[] =>
    sentParams(fetchSpy).map((params) =>
      JSON.parse(params.signed_data as string),
    );

  it('signs share_tag in the reset payload when a tag is given', async () => {
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
      shareTag: ShareTag.RecoverySecret,
    });

    const signed = sentSignedData(fetchSpy);
    expect(signed).toHaveLength(nodeAuthTokens.length);
    expect(
      signed.every((payload) => payload.share_tag === 'recovery_secret'),
    ).toBe(true);
  });

  it('sends share_tag password in the reset payload for the default share', async () => {
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      shareTag: ShareTag.Password,
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
    });

    const signed = sentSignedData(fetchSpy);
    expect(signed.every((payload) => payload.share_tag === 'password')).toBe(
      true,
    );
  });

  it.each([
    {
      label: 'Password reset payload appends share_tag password',
      shareTag: ShareTag.Password,
      suffix: ',"share_tag":"password"',
    },
    {
      label: 'tagged reset payload appends share_tag as the last key',
      shareTag: ShareTag.RecoverySecret,
      suffix: ',"share_tag":"recovery_secret"',
    },
  ])('$label', async ({ shareTag, suffix }) => {
    const timestamp = 1700000000000;
    jest.spyOn(Date, 'now').mockReturnValue(timestamp);
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
      shareTag,
    });

    const expected = nodeAuthTokens
      .map(
        ({ nodeIndex }) =>
          `{"timestamp":${timestamp},"node_index":${nodeIndex},"action":"reset_ratelimit"${suffix}}`,
      )
      .sort();
    const actual = sentParams(fetchSpy)
      .map((params) => params.signed_data as string)
      .sort();
    expect(actual).toStrictEqual(expected);
  });

  it('signs share_tag into the key change proof only when a tag is given', () => {
    const oldAuthPrivKey = 987654321n;
    const shareValue = new BN(1234567);
    const keyShareIndex = 2;
    const nodeIndex = 3;

    /**
     * Checks whether a proof's signature was made by `oldAuthPrivKey` over the
     * snake_case message that includes the given tag (or no tag).
     *
     * @param proof - The key change proof to check.
     * @param tag - The tag expected in the signed message, if any.
     * @returns True when the signature recovers to the old auth public key.
     */
    const signedBy = (proof: KeyChangeProof, tag?: string): boolean => {
      const message = JSON.stringify({
        share_data: Buffer.from(
          shareValue.toArrayLike(Buffer, 'be', 32),
        ).toString('base64'),
        key_share_index: keyShareIndex,
        node_index: nodeIndex,
        timestamp: proof.signatureTimestamp,
        ...(tag !== undefined && { share_tag: tag }),
      });
      const signature = proof.oldKeySignature;
      const recovered = secp256k1.Signature.fromCompact(signature.slice(0, 128))
        .addRecoveryBit(parseInt(signature.slice(128), 16) - 27)
        .recoverPublicKey(keccak256(message));
      return recovered.equals(
        secp256k1.ProjectivePoint.BASE.multiply(oldAuthPrivKey),
      );
    };

    const tagged = utilsModule.createKeyChangeProof(
      shareValue,
      keyShareIndex,
      nodeIndex,
      oldAuthPrivKey,
      ShareTag.RecoverySecret,
    );
    expect(signedBy(tagged, 'recovery_secret')).toBe(true);
    expect(signedBy(tagged)).toBe(false);

    const untagged = utilsModule.createKeyChangeProof(
      shareValue,
      keyShareIndex,
      nodeIndex,
      oldAuthPrivKey,
      ShareTag.Password,
    );
    expect(signedBy(untagged, 'password')).toBe(true);
    expect(signedBy(untagged, 'recovery_secret')).toBe(false);
  });

  it('passes shareTag through to the key change share import items', async () => {
    const spy = jest
      .spyOn(utilsModule, 'generateShareImportItems')
      .mockResolvedValue([] as never);

    await createKeyChangeRequestParams({
      nodeEndpointsMap,
      authTokens: nodeAuthTokens,
      keyShareIndex: 2,
      authConnectionId: 'conn',
      userId: 'user',
      newOprfKey: 1n,
      newAuthPubKey: new Uint8Array([4, 1, 2]),
      oldAuthPrivKey: 1n,
      shareTag: ShareTag.RecoverySecret,
    });

    expect(spy).toHaveBeenCalledWith(
      nodeEndpointsMap,
      nodeAuthTokens,
      1n,
      2,
      new Uint8Array([4, 1, 2]),
      1n,
      ShareTag.RecoverySecret,
    );
  });
});

describe('ToprfSecureBackup share tag pass-through', () => {
  /**
   * Creates a backup client whose node details are fully overridden, so no FND lookup happens.
   *
   * @returns The ToprfSecureBackup instance.
   */
  const createBackup = (): ToprfSecureBackup =>
    new ToprfSecureBackup({
      network: 'sapphire_devnet',
      fetchMetadataAccessCreds: jest.fn() as never,
      nodeDetailsOverride: {
        indexes: nodeIndexes,
        pubKeys: nodeIndexes.map((i) => ({ X: `${i}`, Y: `${i}` })),
        endpoints: nodeIndexes.map((i) => nodeEndpointsMap[i]),
      },
    });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('fetchAuthPubKey passes shareTag to getPubKey', async () => {
    const spy = jest
      .spyOn(getPubKeyModule, 'getPubKey')
      .mockResolvedValue({ authPubKey: new Uint8Array([4]), keyIndex: 1 });

    await createBackup().fetchAuthPubKey({
      nodeAuthTokens,
      authConnectionId: 'conn',
      userId: 'user',
      shareTag: ShareTag.RecoverySecret,
    });

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
  });

  it('recoverEncKey passes shareTag to recovery and to the rate limit reset', async () => {
    const recoverSpy = jest
      .spyOn(toprfEvalRequestModule, 'recoverTOPRFSeed')
      .mockResolvedValue({
        seed: new Uint8Array(32).fill(7),
        keyShareIndex: 1,
      });
    const resetSpy = jest
      .spyOn(resetRateLimitsModule, 'resetRateLimits')
      .mockResolvedValue(true);

    const result = await createBackup().recoverEncKey({
      nodeAuthTokens,
      password: 'password',
      authConnectionId: 'conn',
      userId: 'user',
      shareTag: ShareTag.RecoverySecret,
    });
    await result.rateLimitResetResult;

    expect(recoverSpy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
    expect(resetSpy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
  });

  it('persistLocalKey passes shareTag to storeKeyShares for a new key', async () => {
    const spy = jest
      .spyOn(storeSharesRequestModule, 'storeKeyShares')
      .mockResolvedValue({} as never);

    await createBackup().persistLocalKey({
      nodeAuthTokens,
      oprfKey: 1n,
      authPubKey: new Uint8Array([4]),
      authConnectionId: 'conn',
      userId: 'user',
      shareTag: ShareTag.RecoverySecret,
    });

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
  });

  it('persistLocalKey passes shareTag to changeKeyShares for a key change', async () => {
    const spy = jest
      .spyOn(storeSharesRequestModule, 'changeKeyShares')
      .mockResolvedValue({} as never);

    await createBackup().persistLocalKey({
      nodeAuthTokens,
      oprfKey: 1n,
      authPubKey: new Uint8Array([4]),
      authConnectionId: 'conn',
      userId: 'user',
      keyShareIndex: 2,
      oldAuthKeyPair: { sk: 1n, pk: new Uint8Array([4]) },
      shareTag: ShareTag.RecoverySecret,
    });

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
  });

  it('createAndPersistEncKey passes shareTag to persistLocalKey', async () => {
    const spy = jest
      .spyOn(ToprfSecureBackup.prototype, 'persistLocalKey')
      .mockResolvedValue();

    await createBackup().createAndPersistEncKey({
      nodeAuthTokens,
      password: 'password',
      authConnectionId: 'conn',
      userId: 'user',
      shareTag: ShareTag.RecoverySecret,
    });

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
  });
});

describe('ShareTag.Password is sent explicitly on the wire', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('sends share_tag password on get pub key requests', async () => {
    const fetchSpy = mockJrpcFetch({ pubKey: '04ab', keyIndex: 1 });

    await getPubKey({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      shareTag: ShareTag.Password,
    });

    expect(
      sentParams(fetchSpy).every((params) => params.share_tag === 'password'),
    ).toBe(true);
  });

  it('sends share_tag password on eval requests', async () => {
    const fetchSpy = mockJrpcFetch(emptyEvalResult);

    await recoverTOPRFSeed({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      userInput: toBytes('password'),
      shareTag: ShareTag.Password,
    }).catch(() => undefined);

    expect(fetchSpy).toHaveBeenCalledTimes(nodeAuthTokens.length);
    expect(
      sentParams(fetchSpy).every((params) => params.share_tag === 'password'),
    ).toBe(true);
  });

  it('signs the reset payload with share_tag password', async () => {
    const timestamp = 1700000000000;
    jest.spyOn(Date, 'now').mockReturnValue(timestamp);
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
      shareTag: ShareTag.Password,
    });

    const expected = nodeAuthTokens
      .map(
        ({ nodeIndex }) =>
          `{"timestamp":${timestamp},"node_index":${nodeIndex},"action":"reset_ratelimit","share_tag":"password"}`,
      )
      .sort();
    const actual = sentParams(fetchSpy)
      .map((params) => params.signed_data as string)
      .sort();
    expect(actual).toStrictEqual(expected);
  });

  it('sends shareTag password in store and key change request params', async () => {
    jest
      .spyOn(utilsModule, 'generateShareImportItems')
      .mockResolvedValue([] as never);

    const storeParams = await createStoreKeySharesRequestParams({
      nodeEndpointsMap,
      authTokens: nodeAuthTokens,
      authConnectionId: 'conn',
      userId: 'user',
      keyShareIndex: 1,
      oprfKey: 1n,
      authPubKey: new Uint8Array([4, 1, 2]),
      shareTag: ShareTag.Password,
    });
    const changeParams = await createKeyChangeRequestParams({
      nodeEndpointsMap,
      authTokens: nodeAuthTokens,
      keyShareIndex: 2,
      authConnectionId: 'conn',
      userId: 'user',
      newOprfKey: 1n,
      newAuthPubKey: new Uint8Array([4, 1, 2]),
      oldAuthPrivKey: 1n,
      shareTag: ShareTag.Password,
    });

    expect(storeParams).toHaveProperty('shareTag', 'password');
    expect(changeParams).toHaveProperty('shareTag', 'password');
  });
});

describe('encrypted share plaintext', () => {
  const nodePrivKeyHex = '11'.repeat(32);
  const nodePubKeyHex = Buffer.from(
    secp256k1.getPublicKey(nodePrivKeyHex, false),
  ).toString('hex');
  const nodeTokens: NodeAuthTokens = [
    {
      authToken: Buffer.from('auth-token').toString('base64'),
      nodeIndex: 1,
      nodePubKey: nodePubKeyHex,
    },
  ];
  const endpoints: Record<number, string> = {
    1: 'https://node-1.example/sss/jrpc',
  };

  /**
   * Decrypts the encrypted share of a share import item, the same way a node does.
   *
   * @param encryptedShare - The `encryptedShare` field of a share import item.
   * @returns The decrypted plaintext.
   */
  const decryptShare = async (encryptedShare: string): Promise<Buffer> => {
    const { data, metadata } = JSON.parse(encryptedShare) as {
      data: string;
      metadata: Parameters<typeof encParamsHexToBuf>[0];
    };
    const plaintext = await decrypt(Buffer.from(nodePrivKeyHex, 'hex'), {
      ...encParamsHexToBuf(metadata),
      ciphertext: Buffer.from(data, 'hex'),
    });
    return Buffer.from(plaintext);
  };

  const authPubKeyHex = `04${'ab'.repeat(64)}`;
  const authPubKey = Uint8Array.from(Buffer.from(authPubKeyHex, 'hex'));

  // The plaintext is the v1 payload: the share plus the tag and pub key it is stored under.
  const expectBoundPayload = (plaintext: Buffer, expectedTag: string): void => {
    expect(JSON.parse(plaintext.toString('utf8'))).toStrictEqual({
      v: 1,
      share: expect.any(String),
      share_tag: expectedTag,
      pub_key: authPubKeyHex,
    });
  };

  it.each([
    { label: 'ShareTag.Password', shareTag: ShareTag.Password },
    { label: 'ShareTag.RecoverySecret', shareTag: ShareTag.RecoverySecret },
  ])(
    'binds the share tag and pub key into the plaintext for $label',
    async ({ shareTag }) => {
      const items = await utilsModule.generateShareImportItems(
        endpoints,
        nodeTokens,
        1n,
        1,
        authPubKey,
        undefined,
        shareTag,
      );

      const plaintext = await decryptShare(items[0].encryptedShare);
      expectBoundPayload(plaintext, shareTag);
    },
  );

  it('binds the share tag and pub key into the plaintext for a new share with a tag', async () => {
    const items = await utilsModule.generateShareImportItems(
      endpoints,
      nodeTokens,
      1n,
      1,
      authPubKey,
      undefined,
      ShareTag.RecoverySecret,
    );

    const plaintext = await decryptShare(items[0].encryptedShare);
    expectBoundPayload(plaintext, ShareTag.RecoverySecret);
  });

  it('binds the share tag and pub key into the plaintext for a key change with a tag', async () => {
    const items = await utilsModule.generateShareImportItems<'keyChange'>(
      endpoints,
      nodeTokens,
      1n,
      2,
      authPubKey,
      1n,
      ShareTag.RecoverySecret,
    );

    const plaintext = await decryptShare(items[0].encryptedShare);
    expectBoundPayload(plaintext, ShareTag.RecoverySecret);
  });
});
