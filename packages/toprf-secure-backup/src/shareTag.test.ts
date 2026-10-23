import { toBytes } from '@noble/hashes/utils';

import { ShareTag } from './constants';
import { TOPRFErrorCode } from './errors';
import { getPubKey } from './getPubKeyRequest';
import * as getPubKeyModule from './getPubKeyRequest';
import type { NodeAuthTokens } from './interfaces';
import { MetadataStore } from './metadata';
import { resetRateLimits } from './resetRateLimits';
import * as resetRateLimitsModule from './resetRateLimits';
import * as storeSharesRequestModule from './storeSharesRequest';
import { changeKeyShares, storeKeyShares } from './storeSharesRequest';
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

  it('omits share_tag on get pub key requests when no tag is given', async () => {
    const fetchSpy = mockJrpcFetch({ pubKey: '04ab', keyIndex: 1 });

    await getPubKey({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
    });

    expect(sentParams(fetchSpy)).toHaveLength(nodeAuthTokens.length);
    expect(
      sentParams(fetchSpy).every((params) => !('share_tag' in params)),
    ).toBe(true);
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

  it('omits share_tag on reset rate limit requests when no tag is given', async () => {
    const fetchSpy = mockJrpcFetch(true);

    await resetRateLimits({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId: 'conn',
      userId: 'user',
      authPrivKey: 1n,
    });

    expect(sentShareTags(fetchSpy)).toStrictEqual(
      nodeAuthTokens.map(() => undefined),
    );
  });

  it.each([
    { label: 'with a tag', shareTag: ShareTag.RecoverySecret },
    { label: 'without a tag', shareTag: undefined },
  ])(
    'sends share_tag on eval requests $label and fails on a tagged miss',
    async ({ shareTag }) => {
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
    },
  );

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

  it('changeEncKey passes shareTag to persistLocalKey', async () => {
    const persistSpy = jest
      .spyOn(ToprfSecureBackup.prototype, 'persistLocalKey')
      .mockResolvedValue();
    jest
      .spyOn(MetadataStore.prototype, 'acquireMetadataLock')
      .mockResolvedValue('lock-id');
    jest
      .spyOn(MetadataStore.prototype, 'fetchAllSecretDataItems')
      .mockResolvedValue([
        {
          data: new Uint8Array([1]),
          itemId: 'item',
          version: 'v1',
        },
      ]);
    jest
      .spyOn(MetadataStore.prototype, 'batchAddSecretData')
      .mockResolvedValue(undefined as never);
    jest
      .spyOn(MetadataStore.prototype, 'releaseMetadataLock')
      .mockResolvedValue(undefined as never);

    await createBackup().changeEncKey({
      nodeAuthTokens,
      authConnectionId: 'conn',
      userId: 'user',
      oldEncKey: new Uint8Array(32).fill(1),
      oldPwEncKey: new Uint8Array(32).fill(2),
      oldAuthKeyPair: { sk: 1n, pk: new Uint8Array([4]) },
      newKeyShareIndex: 2,
      newPassword: 'new-password',
      shareTag: ShareTag.RecoverySecret,
    });

    expect(persistSpy).toHaveBeenCalledWith(
      expect.objectContaining({ shareTag: 'recovery_secret' }),
    );
  });
});
