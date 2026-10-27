/* eslint-disable jest/require-top-level-describe -- tests sit inside a conditional `suite` (describe or describe.skip) */

import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { utf8ToBytes } from '@noble/hashes/utils';

import { ShareTag } from './constants';
import { TOPRFErrorCode } from './errors';
import { sendResetRateLimitRequest } from './resetRateLimits';
import { ToprfSecureBackup } from './toprfSecureBackup';
import { createEthereumSignature } from './utils';
import { isLocalNodesEnabled, routeToLocalNodes } from '../tests/localNodes';
import {
  generateIdToken,
  generateMetadataAccessToken,
  generateRandomPassword,
  generateRandomUserId,
} from '../tests/testHelpers';

/*
 * Real-endpoint tests for the share_tag paths.
 *
 * Opt-in: set TOPRF_TEST_E2E=true. Nodes are picked up from the same env as the
 * rest of the suite (TOPRF_TEST_LOCAL_NODES / TOPRF_TEST_METADATA_URL), or devnet by default.
 * The recovery_secret cases need FEATURE_TOPRF_RECOVERY_SECRET=true on the nodes.
 * Each run uses fresh random user ids so no state is shared between runs.
 */
// eslint-disable-next-line n/no-process-env
const runE2E = process.env.TOPRF_TEST_E2E === 'true';
const AUTH_CONNECTION_ID = 'torus-test-health';

/**
 * Hex-encodes bytes so public keys compare by value.
 *
 * @param bytes - The bytes to encode.
 * @returns The lowercase hex string.
 */
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/**
 * Builds a backup instance and authenticates a fresh user against the nodes.
 *
 * @param userId - The user id to authenticate.
 * @returns The backup instance and the node auth tokens.
 */
const authenticateUser = async (
  userId: string,
): Promise<{
  toprfSecureBackup: ToprfSecureBackup;
  nodeAuthTokens: Awaited<
    ReturnType<ToprfSecureBackup['authenticate']>
  >['nodeAuthTokens'];
}> => {
  const toprfSecureBackup = new ToprfSecureBackup({
    fetchMetadataAccessCreds: generateMetadataAccessToken(userId),
    network: 'sapphire_devnet',
  });
  const { nodeAuthTokens } = await toprfSecureBackup.authenticate({
    idTokens: [generateIdToken(userId, 'ES256')],
    authConnectionId: AUTH_CONNECTION_ID,
    userId,
  });
  return { toprfSecureBackup, nodeAuthTokens };
};

const suite = runE2E ? describe : describe.skip;

suite('shareTag e2e (real nodes)', () => {
  if (isLocalNodesEnabled()) {
    routeToLocalNodes();
  }

  it('untagged create then recover returns the same enc key', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const created = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    const recovered = await toprfSecureBackup.recoverEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });

    expect(recovered.encKey).toStrictEqual(created.encKey);
  });

  it('recovery_secret miss is rejected with InsufficientValidResponses', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    // Data exists only under the default (password) tag, so a recovery_secret lookup misses.
    await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });

    await expect(
      toprfSecureBackup.recoverEncKey({
        nodeAuthTokens,
        password,
        authConnectionId: AUTH_CONNECTION_ID,
        userId,
        shareTag: ShareTag.RecoverySecret,
      }),
    ).rejects.toMatchObject({
      // A miss aggregates to InsufficientValidResponses, the same code a fresh-user miss returns for any tag.
      code: TOPRFErrorCode.InsufficientValidResponses,
    });
  });

  it('recovery_secret create then recover with the same tag returns the same enc key', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const created = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    const recovered = await toprfSecureBackup.recoverEncKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });

    expect(recovered.encKey).toStrictEqual(created.encKey);
  });

  it('password and recovery_secret shares stay separate and each recovers its own enc key', async () => {
    const userId = generateRandomUserId();
    const passwordForDefault = generateRandomPassword();
    const passwordForRecovery = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const defaultShare = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password: passwordForDefault,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    const recoveryShare = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      password: passwordForRecovery,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(recoveryShare.encKey).not.toStrictEqual(defaultShare.encKey);

    // Each tag resolves to its own auth public key.
    const defaultPubKey = await toprfSecureBackup.fetchAuthPubKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    const recoveryPubKey = await toprfSecureBackup.fetchAuthPubKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(toHex(defaultPubKey.authPubKey)).toBe(
      toHex(defaultShare.authKeyPair.pk),
    );
    expect(toHex(recoveryPubKey.authPubKey)).toBe(
      toHex(recoveryShare.authKeyPair.pk),
    );
    expect(toHex(recoveryPubKey.authPubKey)).not.toBe(
      toHex(defaultPubKey.authPubKey),
    );

    const recoveredRecovery = await toprfSecureBackup.recoverEncKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      password: passwordForRecovery,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(recoveredRecovery.encKey).toStrictEqual(recoveryShare.encKey);

    const recoveredDefault = await toprfSecureBackup.recoverEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password: passwordForDefault,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(recoveredDefault.encKey).toStrictEqual(defaultShare.encKey);
  });

  it('rejects an unsupported share tag', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    await expect(
      toprfSecureBackup.recoverEncKey({
        nodeAuthTokens,
        password,
        authConnectionId: AUTH_CONNECTION_ID,
        userId,
        shareTag: 'not_a_tag' as ShareTag,
      }),
    ).rejects.toMatchObject({
      // Current behavior: every node rejects with "unsupported tag", but the SDK
      // reports the aggregate failure as a miss, so the node message is not surfaced.
      code: TOPRFErrorCode.InsufficientValidResponses,
    });
  });
});

/*
 * Real-endpoint tests for the signed payloads. The reset signature and the key change
 * proof must cover share_tag, so nodes accept a tagged payload and reject one whose
 * signed tag does not match the request tag.
 */
suite('shareTag signed payload e2e (real nodes)', () => {
  if (isLocalNodesEnabled()) {
    routeToLocalNodes();
  }

  it('accepts a recovery_secret reset whose signed payload carries the tag', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      shareTag: ShareTag.RecoverySecret,
    });
    const recovered = await toprfSecureBackup.recoverEncKey({
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      shareTag: ShareTag.RecoverySecret,
    });

    // Rejects if any node refuses the signed reset.
    expect(await recovered.rateLimitResetResult).toBeUndefined();
  });

  it('rejects a reset signed without the tag when the request targets recovery_secret', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const created = await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      shareTag: ShareTag.RecoverySecret,
    });

    // Correctly signed by the recovery_secret key, but the signed payload omits the tag.
    const { nodeEndpointsMap } = await toprfSecureBackup.getNodeDetails();
    const [{ nodeIndex, authToken }] = nodeAuthTokens;
    const signedData = JSON.stringify({
      timestamp: Date.now(),
      node_index: nodeIndex,
      action: 'reset_ratelimit',
    });
    const response = await sendResetRateLimitRequest(
      nodeEndpointsMap[nodeIndex],
      {
        authToken,
        signature: createEthereumSignature(
          keccak256(utf8ToBytes(signedData)),
          created.authKeyPair.sk,
        ),
        signedData,
        verifier: AUTH_CONNECTION_ID,
        verifierId: userId,
        shareTag: ShareTag.RecoverySecret,
      },
    );

    expect(response.error?.code).toBe(-32603);
    expect(response.error?.message).toBe('Internal error');
    expect(response.error?.data).toBe('Authentication error');
  });

  it('accepts a recovery_secret key change signed by the current recovery_secret key', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const newPassword = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const created = await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      shareTag: ShareTag.RecoverySecret,
    });
    const next = await toprfSecureBackup.createLocalKey({
      password: newPassword,
    });

    await toprfSecureBackup.persistLocalKey({
      nodeAuthTokens,
      oprfKey: next.oprfKey,
      authPubKey: next.authKeyPair.pk,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      keyShareIndex: 2,
      oldAuthKeyPair: created.authKeyPair,
      shareTag: ShareTag.RecoverySecret,
    });

    const recovered = await toprfSecureBackup.recoverEncKey({
      nodeAuthTokens,
      password: newPassword,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      shareTag: ShareTag.RecoverySecret,
    });
    expect(recovered.encKey).toStrictEqual(next.encKey);
  });

  it('persistLocalKey rotates the recovery_secret key and the new auth pubkey is served for that tag', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const created = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    const next = await toprfSecureBackup.createLocalKey({
      password: generateRandomPassword(),
    });

    await toprfSecureBackup.persistLocalKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      oprfKey: next.oprfKey,
      authPubKey: next.authKeyPair.pk,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      keyShareIndex: 2,
      oldAuthKeyPair: created.authKeyPair,
    });

    const pubKey = await toprfSecureBackup.fetchAuthPubKey({
      shareTag: ShareTag.RecoverySecret,
      nodeAuthTokens,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(toHex(pubKey.authPubKey)).toBe(toHex(next.authKeyPair.pk));
  });

  it('rejects a recovery_secret key change signed by the password share key', async () => {
    const userId = generateRandomUserId();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const passwordShare = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password: generateRandomPassword(),
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens,
      password: generateRandomPassword(),
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      shareTag: ShareTag.RecoverySecret,
    });
    const next = await toprfSecureBackup.createLocalKey({
      password: generateRandomPassword(),
    });

    // The proof is signed by the password key, but the change targets the recovery_secret share.
    await expect(
      toprfSecureBackup.persistLocalKey({
        nodeAuthTokens,
        oprfKey: next.oprfKey,
        authPubKey: next.authKeyPair.pk,
        authConnectionId: AUTH_CONNECTION_ID,
        userId,
        keyShareIndex: 2,
        oldAuthKeyPair: passwordShare.authKeyPair,
        shareTag: ShareTag.RecoverySecret,
      }),
    ).rejects.toThrow('Failed to commit nodes');
  });
});

/*
 * Default (untagged) path: no shareTag in the signed payload or in the JSON-RPC request.
 * Nodes must treat it as the password share.
 */
suite('untagged signed payload e2e (real nodes)', () => {
  if (isLocalNodesEnabled()) {
    routeToLocalNodes();
  }

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('password share reset sends share_tag password in the signed data and the request', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });

    const sent: Record<string, unknown>[] = [];
    const originalFetch = global.fetch;
    jest.spyOn(global, 'fetch').mockImplementation((async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      if (typeof init?.body === 'string') {
        const body = JSON.parse(init.body) as {
          method?: string;
          params?: Record<string, unknown>;
        };
        if (body.method === 'TOPRFResetRateLimitRequest' && body.params) {
          sent.push(body.params);
        }
      }
      return originalFetch(input, init);
    }) as never);

    const recovered = await toprfSecureBackup.recoverEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(await recovered.rateLimitResetResult).toBeUndefined();

    expect(sent).not.toHaveLength(0);
    for (const params of sent) {
      expect(params.share_tag).toBe('password');
      expect(JSON.parse(params.signed_data as string).share_tag).toBe(
        'password',
      );
    }
  });

  it('untagged key change succeeds and recovers with the new password', async () => {
    const userId = generateRandomUserId();
    const password = generateRandomPassword();
    const newPassword = generateRandomPassword();
    const { toprfSecureBackup, nodeAuthTokens } =
      await authenticateUser(userId);

    const created = await toprfSecureBackup.createAndPersistEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    const next = await toprfSecureBackup.createLocalKey({
      password: newPassword,
    });

    await toprfSecureBackup.persistLocalKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      oprfKey: next.oprfKey,
      authPubKey: next.authKeyPair.pk,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
      keyShareIndex: 2,
      oldAuthKeyPair: created.authKeyPair,
    });

    const recovered = await toprfSecureBackup.recoverEncKey({
      shareTag: ShareTag.Password,
      nodeAuthTokens,
      password: newPassword,
      authConnectionId: AUTH_CONNECTION_ID,
      userId,
    });
    expect(recovered.encKey).toStrictEqual(next.encKey);
  });
});
