import { utf8ToBytes } from '@noble/ciphers/utils';
import { pbkdf2Async } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha2';
import type { INodePub } from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { EncAccountDataType, FIRST_KEY_INDEX } from './constants';
import { TOPRFError, TOPRFErrorCode } from './errors';
import type { KeyPair, NodeDetailsOverride } from './interfaces';
import { MetadataStore } from './metadata';
import type { KeyDeriver } from './oprf';
import * as resetRateLimitsModule from './resetRateLimits';
import { ToprfSecureBackup } from './toprfSecureBackup';
import {
  generateIdToken,
  generateMetadataAccessToken,
  generateRandomPassword,
  generateRandomUserId,
  sleep,
} from '../tests/testHelpers';

const EXISTING_USER_ID = 'test-verifier-id-existing-user';

const keyDeriver = {
  // Disable eslint-plugin-jsdoc because this is a test file.
  // eslint-disable-next-line jsdoc/require-jsdoc
  deriveKey: async (
    seed: Uint8Array,
    salt: Uint8Array,
  ): Promise<Uint8Array> => {
    return pbkdf2Async(sha256, seed, salt, {
      dkLen: 32,
      c: 500_000,
    });
  },
};

/**
 * Sets up the test environment.
 *
 * @param options - The options for the setup.
 * @param options.authConnectionId - The auth connection id to be used for the test.
 * @param options.userId - The user id to be used for the test.
 * @param options.nodeDetailsOverride - The node details override to be used for the test.
 * @param options.keyDeriver - The key deriver to be used for the test.
 * @returns The setup object.
 */
function setup(options?: {
  authConnectionId?: string;
  userId?: string;
  nodeDetailsOverride?: NodeDetailsOverride;
  keyDeriver?: KeyDeriver;
}): {
  authConnectionId: string;
  userId: string;
  idToken: string;
  toprfSecureBackup: ToprfSecureBackup;
} {
  const authConnectionId = options?.authConnectionId ?? 'torus-test-health';
  const userId = options?.userId ?? generateRandomUserId();
  const idToken = generateIdToken(userId, 'ES256');
  const fetchMetadataAccessCreds = generateMetadataAccessToken(userId);
  const toprfSecureBackup = new ToprfSecureBackup({
    fetchMetadataAccessCreds,
    network: 'sapphire_devnet',
    nodeDetailsOverride: options?.nodeDetailsOverride,
    keyDeriver: options?.keyDeriver,
  });

  return { authConnectionId, userId, idToken, toprfSecureBackup };
}

/**
 * Formats the grouped connection id suffix for the test description.
 *
 * @param connectionId - The connection id to be used for the test.
 * @returns The formatted grouped connection id suffix.
 */
function fmtGroupedConnId(connectionId?: string): string {
  return connectionId
    ? `(with grouped connection id)`
    : '(without grouped connection id)';
}

// TODO: add tests for the scenario when a existing user tries to create a new enc key.
describe('toprf secret backup', function () {
  describe('authenticate', function () {
    [undefined, 'torus-test-health-aggregate'].forEach((groupedConnId) => {
      it(`should be able to authenticate user ${fmtGroupedConnId(groupedConnId)}`, async function () {
        const { authConnectionId, userId, idToken, toprfSecureBackup } =
          setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });
        expect(result).toBeDefined();
        expect(result.nodeAuthTokens).toBeDefined();
        expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
        expect(result.isNewUser).toBe(true);
      });
    });

    it('should return isNewUser as false for existing user', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
        userId: EXISTING_USER_ID,
      });

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      expect(result).toBeDefined();
      expect(result.nodeAuthTokens).toBeDefined();
      expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
      expect(result.isNewUser).toBe(false);
    });

    it('should throw error if unable to fetch node details', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const fndSpy = jest
        .spyOn(NodeDetailManager.prototype, 'getNodeDetails')
        .mockResolvedValueOnce({
          torusIndexes: [],
          torusNodePub: [],
          currentEpoch: '0',
          torusNodeEndpoints: [],
        });

      await expect(
        toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
        }),
      ).rejects.toThrow('Failed to get node details');
      expect(fndSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('#getNodeDetails configurations', function () {
    const MOCK_INDEXES_5 = [1, 2, 3, 4, 5];
    const MOCK_PUBKEYS_5: INodePub[] = [
      { X: '1', Y: '1' },
      { X: '2', Y: '2' },
      { X: '3', Y: '3' },
      { X: '4', Y: '4' },
      { X: '5', Y: '5' },
    ];
    const MOCK_ENDPOINTS_5 = [
      'https://node-1.dev-node.web3auth.io/sss/jrpc',
      'https://node-2.dev-node.web3auth.io/sss/jrpc',
      'https://node-3.dev-node.web3auth.io/sss/jrpc',
      'https://node-4.dev-node.web3auth.io/sss/jrpc',
      'https://node-5.dev-node.web3auth.io/sss/jrpc',
    ];
    const MOCK_ENDPOINT_PATH = '/sss-path';

    let fndSpy: jest.SpyInstance;

    beforeEach(() => {
      fndSpy = jest.spyOn(NodeDetailManager.prototype, 'getNodeDetails');
    });

    afterEach(() => {
      fndSpy.mockRestore();
    });

    describe('when all node details are overridden', () => {
      it('should throw if overridden endpoints array length mismatches overridden indexes length', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            indexes: MOCK_INDEXES_5, // length 5
            pubKeys: MOCK_PUBKEYS_5, // length 5
            endpoints: MOCK_ENDPOINTS_5.slice(0, 4), // length 4
          },
        });
        fndSpy.mockResolvedValue({
          torusNodeEndpoints: [],
          torusIndexes: [],
          torusNodePub: [],
        }); // Should not be called

        await expect(
          toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
          }),
        ).rejects.toThrow(
          'Node details arrays (indexes, pubKeys, endpoints) must have equal lengths',
        );
        expect(fndSpy).not.toHaveBeenCalled();
      });

      it('should throw if overridden pubKeys length mismatches overridden indexes length', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            indexes: MOCK_INDEXES_5, // length 5
            pubKeys: MOCK_PUBKEYS_5.slice(0, 4), // length 4
            endpoints: MOCK_ENDPOINTS_5, // length 5
          },
        });
        fndSpy.mockResolvedValue({
          torusNodeEndpoints: [],
          torusIndexes: [],
          torusNodePub: [],
        }); // Should not be called

        await expect(
          toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
          }),
        ).rejects.toThrow(
          'Node details arrays (indexes, pubKeys, endpoints) must have equal lengths',
        );
        expect(fndSpy).not.toHaveBeenCalled();
      });

      it('should use overridden details and not call FND if all details are validly overridden', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            indexes: MOCK_INDEXES_5,
            pubKeys: MOCK_PUBKEYS_5,
            endpoints: MOCK_ENDPOINTS_5,
          },
        });
        fndSpy.mockResolvedValue({
          torusNodeEndpoints: [],
          torusIndexes: [],
          torusNodePub: [],
        }); // Should not be called

        await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
        });
        expect(fndSpy).not.toHaveBeenCalled();
      });
    });

    describe('when FND service is involved (partial/no overrides)', () => {
      it('should throw if endpoints array length mismatches FND-resolved indexes', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            // indexes and pubKeys not provided
            endpoints: MOCK_ENDPOINTS_5,
          },
        });
        fndSpy.mockResolvedValue({
          torusNodeEndpoints: MOCK_ENDPOINTS_5.slice(0, 3), // FND returns 3 endpoints
          torusIndexes: MOCK_INDEXES_5.slice(0, 3), // FND returns 3 indexes
          torusNodePub: MOCK_PUBKEYS_5.slice(0, 3), // FND returns 3 pubKeys
          currentEpoch: '1',
        });

        await expect(
          toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
          }),
        ).rejects.toThrow(
          'Node details arrays (indexes, pubKeys, endpoints) must have equal lengths',
        );
        expect(fndSpy).toHaveBeenCalled();
      });

      it('should throw if endpoints is path and FND returns no SSS URLs', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            endpoints: MOCK_ENDPOINT_PATH, // endpoint is a path
          },
        });
        fndSpy.mockResolvedValue({
          torusNodeEndpoints: undefined, // FND returns no SSS URLs
          torusIndexes: MOCK_INDEXES_5,
          pubKeys: MOCK_PUBKEYS_5,
          currentEpoch: '1',
        });

        await expect(
          toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
          }),
        ).rejects.toThrow('Failed to get node details');
        expect(fndSpy).toHaveBeenCalled();
      });

      it('should throw if endpoints is undefined and FND returns no SSS URLs', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            endpoints: undefined, // endpoint is undefined
          },
        });
        fndSpy.mockResolvedValue({
          torusNodeEndpoints: [], // FND returns empty SSS URLs
          torusIndexes: MOCK_INDEXES_5,
          pubKeys: MOCK_PUBKEYS_5,
          currentEpoch: '1',
        });

        await expect(
          toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
          }),
        ).rejects.toThrow('Failed to get node details');
        expect(fndSpy).toHaveBeenCalled();
      });

      it('should correctly apply endpoints path to FND-resolved URLs', async () => {
        const { authConnectionId, userId, idToken, toprfSecureBackup } = setup({
          nodeDetailsOverride: {
            endpoints: MOCK_ENDPOINT_PATH, // Provide a path
          },
        });

        fndSpy.mockResolvedValue({
          torusNodeSSSEndpoints: MOCK_ENDPOINTS_5, // Using the live URLs as base
          torusIndexes: MOCK_INDEXES_5,
          torusNodePub: MOCK_PUBKEYS_5,
          currentEpoch: '1',
        });

        let errorMessage: string;
        try {
          await toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
          });
          throw new Error('Expected error to be thrown');
        } catch (error: unknown) {
          errorMessage = (error as Error).message;
        }
        expect(errorMessage).toBeDefined();
        expect(errorMessage).not.toMatch(/Failed to get node details/iu);
        expect(errorMessage).not.toMatch(
          /Node details arrays .* must have equal lengths/iu,
        );

        expect(fndSpy).toHaveBeenCalledTimes(1);
      });

      it('should be able to get node details', async () => {
        const { toprfSecureBackup } = setup();

        fndSpy.mockResolvedValue({
          torusNodeSSSEndpoints: MOCK_ENDPOINTS_5, // Using the live URLs as base
          torusIndexes: MOCK_INDEXES_5,
          torusNodePub: MOCK_PUBKEYS_5,
          currentEpoch: '1',
        });

        const nodeDetails = await toprfSecureBackup.getNodeDetails();

        expect(nodeDetails).toBeDefined();
        expect(nodeDetails.nodeEndpoints).toStrictEqual(MOCK_ENDPOINTS_5);
        expect(nodeDetails.nodeIndexes).toStrictEqual(MOCK_INDEXES_5);
        expect(nodeDetails.nodePubkeys).toStrictEqual(MOCK_PUBKEYS_5);
        expect(fndSpy).toHaveBeenCalledTimes(1);
      });
    });
  });

  describe('createAndPersistEncKey', function () {
    it('should be able to create local enc key', async function () {
      const { toprfSecureBackup } = setup();
      const password = generateRandomPassword();
      const encKey = await toprfSecureBackup.createLocalKey({
        password,
      });
      expect(encKey).toBeDefined();
      expect(encKey.authKeyPair).toBeDefined();
      expect(encKey.authKeyPair.sk).toBeDefined();
      expect(encKey.authKeyPair.pk).toBeDefined();
      expect(encKey.encKey).toBeDefined();

      const encKey2 = await toprfSecureBackup.createLocalKey({
        password,
        oprfKey: encKey.oprfKey,
      });
      expect(encKey2).toBeDefined();
      expect(encKey2.authKeyPair).toBeDefined();
      expect(encKey2.authKeyPair.sk).toBeDefined();
      expect(encKey2.authKeyPair.pk).toBeDefined();
      expect(encKey2.encKey).toBeDefined();

      // same password and scalar should result in same auth key pair and enc key
      expect(encKey2.authKeyPair.sk).toStrictEqual(encKey.authKeyPair.sk);
      expect(encKey2.encKey).toStrictEqual(encKey.encKey);

      const encKey3 = await toprfSecureBackup.createLocalKey({
        password,
      });
      expect(encKey3).toBeDefined();
      expect(encKey3.authKeyPair).toBeDefined();
      expect(encKey3.authKeyPair.sk).toBeDefined();
      expect(encKey3.authKeyPair.pk).toBeDefined();
      expect(encKey3.encKey).toBeDefined();

      expect(encKey3.authKeyPair.sk).not.toStrictEqual(encKey.authKeyPair.sk);
      expect(encKey3.encKey).not.toStrictEqual(encKey.encKey);

      const encKey4 = await toprfSecureBackup.createLocalKey({
        password: generateRandomPassword(),
        oprfKey: encKey3.oprfKey,
      });
      expect(encKey4).toBeDefined();
      expect(encKey4.authKeyPair).toBeDefined();
      expect(encKey4.authKeyPair.sk).toBeDefined();
      expect(encKey4.authKeyPair.pk).toBeDefined();
      expect(encKey4.encKey).toBeDefined();

      expect(encKey4.authKeyPair.sk).not.toStrictEqual(encKey.authKeyPair.sk);
      expect(encKey4.encKey).not.toStrictEqual(encKey.encKey);
    });

    [undefined, 'torus-test-health-aggregate'].forEach((groupedConnId) => {
      it(`should be able to create and persist enc key ${fmtGroupedConnId(groupedConnId)}`, async function () {
        const { authConnectionId, userId, idToken, toprfSecureBackup } =
          setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });
        expect(result.isNewUser).toBe(true);
        const encKey = await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: generateRandomPassword(),
          authConnectionId,
          userId,
        });
        expect(encKey).toBeDefined();
        expect(encKey.authKeyPair).toBeDefined();
        expect(encKey.authKeyPair.sk).toBeDefined();
        expect(encKey.authKeyPair.pk).toBeDefined();
        expect(encKey.encKey).toBeDefined();
      });
    });

    it('should throw error if user is not authenticated while creating enc key', async function () {
      const { authConnectionId, userId, toprfSecureBackup } = setup();

      await expect(
        toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: [],
          password: generateRandomPassword(),
          authConnectionId,
          userId,
        }),
      ).rejects.toBeDefined();
    });

    it('should throw error if invalid auth tokens are provided', async function () {
      const { authConnectionId, userId, toprfSecureBackup } = setup();
      const INVALID_NODE_AUTH_TOKENS = [
        {
          nodeIndex: 1,
          authToken: 'invalid auth token',
          nodePubKey:
            '04b56541684ea5fa40c8337b7688d502f0e9e092098962ad344c34e94f06d293fb759a998cef79d389082f9a75061a29190eec0cac99b8c25ddcf6b58569dad55c',
        },
        {
          nodeIndex: 2,
          authToken: 'invalid auth token',
          nodePubKey:
            '04b56541684ea5fa40c8337b7688d502f0e9e092098962ad344c34e94f06d293fb759a998cef79d389082f9a75061a29190eec0cac99b8c25ddcf6b58569dad55c',
        },
        {
          nodeIndex: 3,
          authToken: 'invalid auth token',
          nodePubKey:
            '04b56541684ea5fa40c8337b7688d502f0e9e092098962ad344c34e94f06d293fb759a998cef79d389082f9a75061a29190eec0cac99b8c25ddcf6b58569dad55c',
        },
        {
          nodeIndex: 4,
          authToken: 'invalid auth token',
          nodePubKey:
            '04b56541684ea5fa40c8337b7688d502f0e9e092098962ad344c34e94f06d293fb759a998cef79d389082f9a75061a29190eec0cac99b8c25ddcf6b58569dad55c',
        },
      ];

      await expect(
        toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: INVALID_NODE_AUTH_TOKENS,
          password: generateRandomPassword(),
          authConnectionId,
          userId,
        }),
      ).rejects.toThrow(TOPRFError.invalidAuthToken());
    });
  });
  describe('recoverEncKey', function () {
    [undefined, 'torus-test-health-aggregate'].forEach((groupedConnId) => {
      it(`should recover enc key ${fmtGroupedConnId(groupedConnId)}`, async function () {
        // Test with and without optional key deriver.
        const keyDerivers = [undefined, keyDeriver];
        for (const kd of keyDerivers) {
          const { authConnectionId, userId, idToken, toprfSecureBackup } =
            setup({
              keyDeriver: kd,
            });

          const result = await toprfSecureBackup.authenticate({
            idTokens: [idToken],
            authConnectionId,
            userId,
            groupedAuthConnectionId: groupedConnId,
          });

          const password = generateRandomPassword();
          const encKey = await toprfSecureBackup.createAndPersistEncKey({
            nodeAuthTokens: result.nodeAuthTokens,
            password,
            authConnectionId,
            userId,
          });

          const recoveredEncKey = await toprfSecureBackup.recoverEncKey({
            nodeAuthTokens: result.nodeAuthTokens,
            password,
            authConnectionId,
            userId,
            groupedAuthConnectionId: groupedConnId,
          });
          expect(recoveredEncKey).toBeDefined();
          expect(recoveredEncKey.authKeyPair).toBeDefined();
          expect(recoveredEncKey.authKeyPair.sk).toBeDefined();
          expect(recoveredEncKey.authKeyPair.pk).toBeDefined();
          expect(recoveredEncKey.encKey).toBeDefined();
          expect(recoveredEncKey.keyShareIndex).toBeDefined();
          expect(await recoveredEncKey.rateLimitResetResult).toBeUndefined();

          expect(recoveredEncKey.authKeyPair.sk).toStrictEqual(
            encKey.authKeyPair.sk,
          );
          expect(recoveredEncKey.encKey).toStrictEqual(encKey.encKey);
          expect(recoveredEncKey.authKeyPair.pk).toStrictEqual(
            encKey.authKeyPair.pk,
          );
        }
      });
    });

    it('should recover enc key even when rate limit reset fails', async function () {
      const mockResetRateLimits = jest
        .spyOn(resetRateLimitsModule, 'resetRateLimits')
        .mockImplementation(async () =>
          Promise.reject(TOPRFError.pwdInputRateLimitExceeded()),
        );

      try {
        const { authConnectionId, userId, idToken, toprfSecureBackup } =
          setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
        });

        const password = generateRandomPassword();
        const encKey = await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password,
          authConnectionId,
          userId,
        });

        const recoveredKey = await toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password,
          authConnectionId,
          userId,
        });

        // Main functionality should work
        expect(recoveredKey.authKeyPair).toBeDefined();
        expect(recoveredKey.encKey).toBeDefined();
        expect(recoveredKey.authKeyPair.sk).toStrictEqual(
          encKey.authKeyPair.sk,
        );
        expect(recoveredKey.encKey).toStrictEqual(encKey.encKey);
        expect(recoveredKey.keyShareIndex).toBeDefined();

        // Rate limit reset should fail
        await expect(recoveredKey.rateLimitResetResult).rejects.toThrow(
          TOPRFError.pwdInputRateLimitExceeded(),
        );

        expect(mockResetRateLimits).toHaveBeenCalled();
      } finally {
        mockResetRateLimits.mockRestore();
      }
    });

    it('should throw `TOPRFError.couldNotDeriveEncryptionKey` when the incorrect password is provided', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const password = generateRandomPassword();
      await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        authConnectionId,
        userId,
      });

      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: 'INCORRECT_PASSWORD',
          authConnectionId,
          userId,
        }),
      ).rejects.toThrow(TOPRFError.couldNotDeriveEncryptionKey());
    });

    it('should trigger rate limiting after multiple incorrect password attempts but allow correct password', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const authResult = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const correctPassword = generateRandomPassword();
      await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: authResult.nodeAuthTokens,
        password: correctPassword,
        authConnectionId,
        userId,
      });

      const incorrectPassword = generateRandomPassword();

      // First 3 attempts with incorrect password should fail normally
      for (let i = 0; i < 3; i++) {
        await expect(
          toprfSecureBackup.recoverEncKey({
            nodeAuthTokens: authResult.nodeAuthTokens,
            password: incorrectPassword,
            authConnectionId,
            userId,
          }),
        ).rejects.toThrow(TOPRFError.couldNotDeriveEncryptionKey());
      }

      // 4th attempt with incorrect password should trigger rate limiting
      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: authResult.nodeAuthTokens,
          password: incorrectPassword,
          authConnectionId,
          userId,
        }),
      ).rejects.toMatchObject({
        code: TOPRFErrorCode.RateLimitExceeded,
        message: expect.stringContaining('Rate limit error from server'),
        meta: {
          rateLimitDetails: {
            message: expect.any(String),
            remainingTime: 30,
          },
        },
      });

      // next attempt (within the rate limit period) should fail even with the correct password
      // 3rd attempt with incorrect password should trigger rate limiting
      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: authResult.nodeAuthTokens,
          password: incorrectPassword,
          authConnectionId,
          userId,
        }),
      ).rejects.toMatchObject({
        code: TOPRFErrorCode.RateLimitExceeded,
        message: expect.stringContaining('Rate limit error from server'),
        meta: {
          rateLimitDetails: {
            message: expect.any(String),
            remainingTime: expect.any(Number),
          },
        },
      });

      // Wait for the rate limit period, 30 seconds
      await sleep(30_000);

      // Attempt with the correct password should succeed and reset rate limit
      const recoveredKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: authResult.nodeAuthTokens,
        password: correctPassword,
        authConnectionId,
        userId,
      });
      expect(recoveredKey).toBeDefined();
      expect(recoveredKey.authKeyPair).toBeDefined();
      expect(recoveredKey.encKey).toBeDefined();
      expect(await recoveredKey.rateLimitResetResult).toBeUndefined();

      // Subsequent attempt with incorrect password should fail normally again
      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: authResult.nodeAuthTokens,
          password: incorrectPassword,
          authConnectionId,
          userId,
        }),
      ).rejects.toThrow(TOPRFError.couldNotDeriveEncryptionKey());
    }, 40000);
  });

  describe('changeEncKey', function () {
    [undefined, 'torus-test-health-aggregate'].forEach((groupedConnId) => {
      it(`should be able to change encryption key and recover password for ${fmtGroupedConnId(groupedConnId) ? 'aggregate' : 'normal'} verifier`, async function () {
        const secretData = utf8ToBytes('test-secret-data-for-key-change');
        const { authConnectionId, userId, idToken, toprfSecureBackup } =
          setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });
        expect(result.nodeAuthTokens).toBeDefined();
        expect(result.nodeAuthTokens.length).toBeGreaterThan(0);

        const originalPassword = generateRandomPassword();
        const originalEncKeyResult =
          await toprfSecureBackup.createAndPersistEncKey({
            nodeAuthTokens: result.nodeAuthTokens,
            password: originalPassword,
            authConnectionId,
            userId,
          });

        await toprfSecureBackup.addSecretDataItem({
          encKey: originalEncKeyResult.encKey,
          secretData,
          authKeyPair: originalEncKeyResult.authKeyPair,
          dataType: EncAccountDataType.PrimarySrp,
        });

        const originalSecretData =
          await toprfSecureBackup.fetchAllSecretDataItems({
            decKey: originalEncKeyResult.encKey,
            authKeyPair: originalEncKeyResult.authKeyPair,
          });
        expect(originalSecretData).not.toBeNull();
        expect(originalSecretData?.length).toBe(1);
        expect(originalSecretData?.[0].data).toStrictEqual(secretData);
        expect(originalSecretData?.[0].dataType).toBe(
          EncAccountDataType.PrimarySrp,
        );

        // Recover the original key to get the keyShareIndex
        const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });

        expect(recoveredOriginalKey.keyShareIndex).toBe(FIRST_KEY_INDEX);

        // Fetching enc key from history should fail, because enc key was not backed up yet.
        await expect(
          toprfSecureBackup.recoverPwEncKey({
            targetAuthPubKey: recoveredOriginalKey.authKeyPair.pk,
            curPwEncKey: originalEncKeyResult.pwEncKey,
            curAuthKeyPair: originalEncKeyResult.authKeyPair,
          }),
        ).rejects.toThrow(
          TOPRFError.couldNotFetchPassword(
            'Failed to get previous password and keys',
          ),
        );

        // Change to a new encryption key
        const newPassword = generateRandomPassword();
        const newEncKeyResult = await toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          groupedAuthConnectionId: groupedConnId,
          userId,
          oldEncKey: originalEncKeyResult.encKey,
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          newPassword,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
        });
        expect(newEncKeyResult).toBeDefined();
        expect(newEncKeyResult.authKeyPair).toBeDefined();
        expect(newEncKeyResult.encKey).toBeDefined();

        const recoveredNewKey = await toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: newPassword,
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });

        expect(recoveredNewKey.keyShareIndex).toBe(
          recoveredOriginalKey.keyShareIndex + 1,
        );

        // Verify the new key can access the data with dataType preserved
        const newSecretData = await toprfSecureBackup.fetchAllSecretDataItems({
          decKey: recoveredNewKey.encKey,
          authKeyPair: recoveredNewKey.authKeyPair,
        });
        expect(newSecretData).not.toBeNull();
        expect(newSecretData?.length).toBe(1);
        expect(newSecretData?.[0].data).toStrictEqual(secretData);
        expect(newSecretData?.[0].dataType).toBe(EncAccountDataType.PrimarySrp);

        // Verify the key change was actually effective by comparing the recovered keys
        expect(recoveredNewKey.authKeyPair.sk).toStrictEqual(
          newEncKeyResult.authKeyPair.sk,
        );
        expect(recoveredNewKey.authKeyPair.pk).toStrictEqual(
          newEncKeyResult.authKeyPair.pk,
        );

        // Verify the old key pair is different from the new key pair
        expect(recoveredNewKey.authKeyPair.sk).not.toStrictEqual(
          originalEncKeyResult.authKeyPair.sk,
        );
        expect(recoveredNewKey.authKeyPair.pk).not.toStrictEqual(
          originalEncKeyResult.authKeyPair.pk,
        );
        expect(recoveredNewKey.encKey).not.toStrictEqual(
          originalEncKeyResult.encKey,
        );

        // Verify that we can recover old enc key.
        const recoveredKey = await toprfSecureBackup.recoverPwEncKey({
          targetAuthPubKey: originalEncKeyResult.authKeyPair.pk,
          curPwEncKey: newEncKeyResult.pwEncKey,
          curAuthKeyPair: newEncKeyResult.authKeyPair,
        });
        expect(recoveredKey.pwEncKey).toStrictEqual(
          originalEncKeyResult.pwEncKey,
        );

        // Change password again.
        const newPassword2 = generateRandomPassword();
        const newEncKeyResult2 = await toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          groupedAuthConnectionId: groupedConnId,
          userId,
          oldEncKey: newEncKeyResult.encKey,
          oldPwEncKey: newEncKeyResult.pwEncKey,
          oldAuthKeyPair: newEncKeyResult.authKeyPair,
          newPassword: newPassword2,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 2,
        });

        // Verify that we can recover old enc key.
        const recoveredKey2 = await toprfSecureBackup.recoverPwEncKey({
          targetAuthPubKey: originalEncKeyResult.authKeyPair.pk,
          curPwEncKey: newEncKeyResult2.pwEncKey,
          curAuthKeyPair: newEncKeyResult2.authKeyPair,
        });
        expect(recoveredKey2.pwEncKey).toStrictEqual(
          originalEncKeyResult.pwEncKey,
        );

        // Verify that we can recover new enc key.
        const recoveredKey3 = await toprfSecureBackup.recoverPwEncKey({
          targetAuthPubKey: newEncKeyResult.authKeyPair.pk,
          curPwEncKey: newEncKeyResult2.pwEncKey,
          curAuthKeyPair: newEncKeyResult2.authKeyPair,
        });
        expect(recoveredKey3.pwEncKey).toStrictEqual(newEncKeyResult.pwEncKey);

        // Enc key recovery should fail when we limit the password chain length
        await expect(
          toprfSecureBackup.recoverPwEncKey({
            targetAuthPubKey: originalEncKeyResult.authKeyPair.pk,
            curPwEncKey: newEncKeyResult2.pwEncKey,
            curAuthKeyPair: newEncKeyResult2.authKeyPair,
            maxPwChainLength: 1,
          }),
        ).rejects.toThrow(TOPRFError.maxKeyChainLengthExceeded());
      });
      it(`should be able to change encryption key and recover password for ${fmtGroupedConnId(groupedConnId) ? 'aggregate' : 'normal'} verifier using pregenerated OPRF key`, async function () {
        const secretData = utf8ToBytes('test-secret-data-for-key-change');
        const { authConnectionId, userId, idToken, toprfSecureBackup } =
          setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });
        expect(result.nodeAuthTokens).toBeDefined();
        expect(result.nodeAuthTokens.length).toBeGreaterThan(0);

        const originalPassword = generateRandomPassword();
        const originalEncKeyResult =
          await toprfSecureBackup.createAndPersistEncKey({
            nodeAuthTokens: result.nodeAuthTokens,
            password: originalPassword,
            authConnectionId,
            userId,
          });

        await toprfSecureBackup.addSecretDataItem({
          encKey: originalEncKeyResult.encKey,
          secretData,
          authKeyPair: originalEncKeyResult.authKeyPair,
          dataType: EncAccountDataType.PrimarySrp,
        });

        const originalSecretData =
          await toprfSecureBackup.fetchAllSecretDataItems({
            decKey: originalEncKeyResult.encKey,
            authKeyPair: originalEncKeyResult.authKeyPair,
          });
        expect(originalSecretData).not.toBeNull();
        expect(originalSecretData?.length).toBe(1);
        expect(originalSecretData?.[0].data).toStrictEqual(secretData);
        expect(originalSecretData?.[0].dataType).toBe(
          EncAccountDataType.PrimarySrp,
        );

        // Recover the original key to get the keyShareIndex
        const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });

        expect(recoveredOriginalKey.keyShareIndex).toBe(FIRST_KEY_INDEX);

        // Fetching enc key from history should fail, because enc key was not backed up yet.
        await expect(
          toprfSecureBackup.recoverPwEncKey({
            targetAuthPubKey: recoveredOriginalKey.authKeyPair.pk,
            curPwEncKey: originalEncKeyResult.pwEncKey,
            curAuthKeyPair: originalEncKeyResult.authKeyPair,
          }),
        ).rejects.toThrow(
          TOPRFError.couldNotFetchPassword(
            'Failed to get previous password and keys',
          ),
        );

        // Change to a new encryption key
        const newPassword = generateRandomPassword();
        const pregeneratedOprfKey = await toprfSecureBackup.createLocalKey({
          password: newPassword,
        });
        const newEncKeyResult = await toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          groupedAuthConnectionId: groupedConnId,
          userId,
          oldEncKey: originalEncKeyResult.encKey,
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          pregeneratedOprfKey,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
        });
        expect(newEncKeyResult).toBeDefined();
        expect(newEncKeyResult.authKeyPair).toBeDefined();
        expect(newEncKeyResult.encKey).toBeDefined();

        const recoveredNewKey = await toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: newPassword,
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });

        expect(recoveredNewKey.keyShareIndex).toBe(
          recoveredOriginalKey.keyShareIndex + 1,
        );

        // Verify the new key can access the data with dataType preserved
        const newSecretData = await toprfSecureBackup.fetchAllSecretDataItems({
          decKey: recoveredNewKey.encKey,
          authKeyPair: recoveredNewKey.authKeyPair,
        });
        expect(newSecretData).not.toBeNull();
        expect(newSecretData?.length).toBe(1);
        expect(newSecretData?.[0].data).toStrictEqual(secretData);
        expect(newSecretData?.[0].dataType).toBe(EncAccountDataType.PrimarySrp);

        // Verify the key change was actually effective by comparing the recovered keys
        expect(recoveredNewKey.authKeyPair.sk).toStrictEqual(
          newEncKeyResult.authKeyPair.sk,
        );
        expect(recoveredNewKey.authKeyPair.pk).toStrictEqual(
          newEncKeyResult.authKeyPair.pk,
        );

        // Verify the old key pair is different from the new key pair
        expect(recoveredNewKey.authKeyPair.sk).not.toStrictEqual(
          originalEncKeyResult.authKeyPair.sk,
        );
        expect(recoveredNewKey.authKeyPair.pk).not.toStrictEqual(
          originalEncKeyResult.authKeyPair.pk,
        );
        expect(recoveredNewKey.encKey).not.toStrictEqual(
          originalEncKeyResult.encKey,
        );

        // Verify that we can recover old enc key.
        const recoveredKey = await toprfSecureBackup.recoverPwEncKey({
          targetAuthPubKey: originalEncKeyResult.authKeyPair.pk,
          curPwEncKey: newEncKeyResult.pwEncKey,
          curAuthKeyPair: newEncKeyResult.authKeyPair,
        });
        expect(recoveredKey.pwEncKey).toStrictEqual(
          originalEncKeyResult.pwEncKey,
        );

        // Change password again.
        const newPassword2 = generateRandomPassword();
        const newEncKeyResult2 = await toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          groupedAuthConnectionId: groupedConnId,
          userId,
          oldEncKey: newEncKeyResult.encKey,
          oldPwEncKey: newEncKeyResult.pwEncKey,
          oldAuthKeyPair: newEncKeyResult.authKeyPair,
          newPassword: newPassword2,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 2,
        });

        // Verify that we can recover old enc key.
        const recoveredKey2 = await toprfSecureBackup.recoverPwEncKey({
          targetAuthPubKey: originalEncKeyResult.authKeyPair.pk,
          curPwEncKey: newEncKeyResult2.pwEncKey,
          curAuthKeyPair: newEncKeyResult2.authKeyPair,
        });
        expect(recoveredKey2.pwEncKey).toStrictEqual(
          originalEncKeyResult.pwEncKey,
        );

        // Verify that we can recover new enc key.
        const recoveredKey3 = await toprfSecureBackup.recoverPwEncKey({
          targetAuthPubKey: newEncKeyResult.authKeyPair.pk,
          curPwEncKey: newEncKeyResult2.pwEncKey,
          curAuthKeyPair: newEncKeyResult2.authKeyPair,
        });
        expect(recoveredKey3.pwEncKey).toStrictEqual(newEncKeyResult.pwEncKey);

        // Enc key recovery should fail when we limit the password chain length
        await expect(
          toprfSecureBackup.recoverPwEncKey({
            targetAuthPubKey: originalEncKeyResult.authKeyPair.pk,
            curPwEncKey: newEncKeyResult2.pwEncKey,
            curAuthKeyPair: newEncKeyResult2.authKeyPair,
            maxPwChainLength: 1,
          }),
        ).rejects.toThrow(TOPRFError.maxKeyChainLengthExceeded());
      });
    });

    // The metadata lock has a 90 second expiry time and will auto-release after that period,
    // regardless of whether the key change succeeded or failed.
    // While changeEncKey() attempts to manually release the lock after a successful key change,
    // any failure to release the lock should not impact the overall key change operation.
    it('should not throw error when failed to released metadata lock', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-key-change');
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      // Recover the original key to get the keyShareIndex
      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        authConnectionId,
        userId,
      });

      const releaseMetadataLockSpy = jest
        .spyOn(MetadataStore.prototype, 'releaseMetadataLock')
        .mockRejectedValue(new Error('Failed to release lock'));

      // Change to a new encryption key
      const newPassword = generateRandomPassword();
      const newEncKeyResult = await toprfSecureBackup.changeEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        authConnectionId,
        userId,
        oldEncKey: originalEncKeyResult.encKey,
        oldPwEncKey: originalEncKeyResult.pwEncKey,
        oldAuthKeyPair: originalEncKeyResult.authKeyPair,
        newPassword,
        newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
      });
      expect(newEncKeyResult).toBeDefined();
      expect(newEncKeyResult.authKeyPair).toBeDefined();
      expect(newEncKeyResult.encKey).toBeDefined();

      expect(releaseMetadataLockSpy).toHaveBeenCalled();
    });

    it('should throw error when trying to change encryption key without existing data', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      // Creating keys but intentionally not storing any secret data
      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
        });

      const newPassword = generateRandomPassword();

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          userId,
          oldEncKey: originalEncKeyResult.encKey,
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          newPassword,
          newKeyShareIndex: FIRST_KEY_INDEX + 1,
        }),
      ).rejects.toThrow('No existing data found to change key');
    });

    it('should throw error when metadata server fails during change encryption key', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-metadata-failure');
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      // Setup initial data
      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        authConnectionId,
        userId,
      });

      // Mock MetadataStore.batchAddSecretData to throw an error
      const batchAddSecretDataSpy = jest.spyOn(
        MetadataStore.prototype,
        'batchAddSecretData',
      );
      batchAddSecretDataSpy.mockRejectedValue(
        new Error('Metadata server failed during batch data update'),
      );

      const newPassword = generateRandomPassword();
      try {
        // Attempt to change the encryption key - should fail during batch data update
        await expect(
          toprfSecureBackup.changeEncKey({
            nodeAuthTokens: result.nodeAuthTokens,
            authConnectionId,
            userId,
            oldEncKey: originalEncKeyResult.encKey,
            oldPwEncKey: originalEncKeyResult.pwEncKey,
            oldAuthKeyPair: originalEncKeyResult.authKeyPair,
            newPassword,
            newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
          }),
        ).rejects.toThrow('Metadata server failed during batch data update');

        expect(batchAddSecretDataSpy).toHaveBeenCalled();
      } finally {
        jest.restoreAllMocks();
      }

      // verify the key cannot be recovered using the new password
      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: newPassword,
          authConnectionId,
          userId,
        }),
      ).rejects.toThrow('Could not derive encryption key');
    });

    it('should throw error when using incorrect authKeyPair during password change', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-incorrect-auth');
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        authConnectionId,
        userId,
      });

      // Generate incorrect authKeyPair
      const differentPassword = generateRandomPassword();
      const incorrectKeyResult = await toprfSecureBackup.createLocalKey({
        password: differentPassword,
      });

      const newPassword = generateRandomPassword();

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          userId,
          oldEncKey: originalEncKeyResult.encKey,
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: incorrectKeyResult.authKeyPair, // Using incorrect authKeyPair
          newPassword,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
        }),
      ).rejects.toThrow('No existing data found to change key');
    });

    it('should throw error when using incorrect encryption key during password change', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-incorrect-enc-key');
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        authConnectionId,
        userId,
      });

      // Generate incorrect encryption key
      const differentPassword = generateRandomPassword();
      const incorrectKeyResult = await toprfSecureBackup.createLocalKey({
        password: differentPassword,
      });

      const newPassword = generateRandomPassword();

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          userId,
          oldEncKey: incorrectKeyResult.encKey, // Using incorrect encKey
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          newPassword,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
        }),
      ).rejects.toThrow(
        'failed to fetch metadata: failed to fetch metadata: aes/gcm: invalid ghash tag',
      );
    });

    it('should throw error if none of newPassword or pregeneratedOprfKey is provided or if both are provided', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      // Creating keys but intentionally not storing any secret data
      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          authConnectionId,
          userId,
        });

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          userId,
          oldEncKey: originalEncKeyResult.encKey,
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          newKeyShareIndex: FIRST_KEY_INDEX + 1,
        }),
      ).rejects.toThrow(
        'Either newPassword or pregeneratedOprfKey is required',
      );

      const newPassword = generateRandomPassword();
      const pregeneratedOprfKey = await toprfSecureBackup.createLocalKey({
        password: newPassword,
      });
      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          userId,
          newPassword,
          pregeneratedOprfKey,
          oldEncKey: originalEncKeyResult.encKey,
          oldPwEncKey: originalEncKeyResult.pwEncKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          newKeyShareIndex: FIRST_KEY_INDEX + 1,
        }),
      ).rejects.toThrow(
        'Only one of newPassword or pregeneratedOprfKey is allowed',
      );
    });
  });

  describe('addSecretDataItem', function () {
    it('should be able to store secret data', async function () {
      const secretData = utf8ToBytes('test-secret-data');
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });
      const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: generateRandomPassword(),
        authConnectionId,
        userId,
      });

      await toprfSecureBackup.addSecretDataItem({
        encKey: encKeyResult.encKey,
        secretData,
        authKeyPair: encKeyResult.authKeyPair,
        dataType: EncAccountDataType.PrimarySrp,
      });

      const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems(
        {
          decKey: encKeyResult.encKey,
          authKeyPair: encKeyResult.authKeyPair,
        },
      );
      expect(fetchedSecretData).not.toBeNull();
      expect(fetchedSecretData?.[0].data).toStrictEqual(secretData);
      expect(fetchedSecretData?.[0].dataType).toBe(
        EncAccountDataType.PrimarySrp,
      );
      expect(fetchedSecretData?.[0].createdAt).toBeDefined();
    });
  });

  describe('batchAddSecretDataItems', function () {
    const secretDataArray = [
      {
        data: utf8ToBytes('test-secret-data-1'),
        dataType: EncAccountDataType.PrimarySrp,
      },
      {
        data: utf8ToBytes('test-secret-data-2'),
        dataType: EncAccountDataType.ImportedSrp,
      },
      { data: utf8ToBytes('test-secret-data-3') },
    ];
    const password = generateRandomPassword();

    let toprfSecureBackup: ToprfSecureBackup;
    let encKey: Uint8Array;
    let authKeyPair: KeyPair;

    beforeEach(async function () {
      const {
        authConnectionId,
        userId,
        idToken,
        toprfSecureBackup: _toprfSecureBackup,
      } = setup();
      toprfSecureBackup = _toprfSecureBackup;

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });

      const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        authConnectionId,
        userId,
      });
      encKey = encKeyResult.encKey;
      authKeyPair = encKeyResult.authKeyPair;
    });

    afterEach(function () {
      jest.restoreAllMocks();
    });

    it('should be able to store secret data in batch', async function () {
      await toprfSecureBackup.batchAddSecretDataItems({
        items: secretDataArray,
        encKey,
        authKeyPair,
      });

      const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems(
        {
          decKey: encKey,
          authKeyPair,
        },
      );

      expect(fetchedSecretData).toHaveLength(secretDataArray.length);

      // Sort both arrays to compare content regardless of order
      const sortedSecretDataArray = secretDataArray
        .map((item) => item.data)
        .sort();
      const sortedFetchedSecretData = fetchedSecretData
        .map((item) => item.data)
        .sort();
      expect(sortedFetchedSecretData).toStrictEqual(sortedSecretDataArray);

      // Verify dataType values
      const itemsWithDataType = fetchedSecretData.filter(
        (item) => item.dataType !== undefined,
      );
      expect(itemsWithDataType).toHaveLength(2);
      expect(
        itemsWithDataType.some(
          (item) => item.dataType === EncAccountDataType.PrimarySrp,
        ),
      ).toBe(true);
      expect(
        itemsWithDataType.some(
          (item) => item.dataType === EncAccountDataType.ImportedSrp,
        ),
      ).toBe(true);

      // Verify one item has no dataType
      const itemsWithoutDataType = fetchedSecretData.filter(
        (item) => item.dataType === undefined,
      );
      expect(itemsWithoutDataType).toHaveLength(1);

      // Verify all items have createdAt
      fetchedSecretData.forEach((item) => {
        expect(item.createdAt).toBeDefined();
      });
    });

    it('should throw an error when failed to acquire metadata lock', async function () {
      jest
        .spyOn(MetadataStore.prototype, 'acquireMetadataLock')
        .mockRejectedValue(new Error('Failed to acquire metadata lock'));

      await expect(
        toprfSecureBackup.batchAddSecretDataItems({
          items: secretDataArray,
          encKey,
          authKeyPair,
        }),
      ).rejects.toThrow('Failed to acquire metadata lock');
    });

    // The metadata lock has a 90 second expiry time and will auto-release after that period,
    // regardless of whether the key change succeeded or failed.
    // While changeEncKey() attempts to manually release the lock after a successful key change,
    // any failure to release the lock should not impact the overall key change operation.
    it('should `not` throw an error when failed to release metadata lock', async function () {
      jest
        .spyOn(MetadataStore.prototype, 'releaseMetadataLock')
        .mockRejectedValue(new Error('Failed to release metadata lock'));

      await toprfSecureBackup.batchAddSecretDataItems({
        items: secretDataArray,
        encKey,
        authKeyPair,
      });

      const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems(
        {
          decKey: encKey,
          authKeyPair,
        },
      );

      expect(fetchedSecretData).toHaveLength(secretDataArray.length);

      // Sort both arrays to compare content regardless of order
      const sortedSecretDataArray = secretDataArray
        .map((item) => item.data)
        .sort();
      const sortedFetchedSecretData = fetchedSecretData
        .map((item) => item.data)
        .sort();
      expect(sortedFetchedSecretData).toStrictEqual(sortedSecretDataArray);

      // Verify dataType values
      const itemsWithDataType = fetchedSecretData.filter(
        (item) => item.dataType !== undefined,
      );
      expect(itemsWithDataType).toHaveLength(2);

      // Verify all items have createdAt
      fetchedSecretData.forEach((item) => {
        expect(item.createdAt).toBeDefined();
      });
    });
  });

  describe('updateSecretDataItem', function () {
    it('should update fields for existing item', async function () {
      const secretData = utf8ToBytes('test-secret-data');
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });
      const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: generateRandomPassword(),
        authConnectionId,
        userId,
      });

      // Add item without dataType (simulates old data that needs migration)
      await toprfSecureBackup.addSecretDataItem({
        encKey: encKeyResult.encKey,
        secretData,
        authKeyPair: encKeyResult.authKeyPair,
      });

      const beforeUpdate = await toprfSecureBackup.fetchAllSecretDataItems({
        decKey: encKeyResult.encKey,
        authKeyPair: encKeyResult.authKeyPair,
      });
      expect(beforeUpdate).toHaveLength(1);
      expect(beforeUpdate[0].dataType).toBeUndefined();
      expect(beforeUpdate[0].createdAt).toBeDefined();

      // Use the actual itemId returned from fetch (server generates/hashes it)
      const { itemId, createdAt: originalCreatedAt } = beforeUpdate[0];
      expect(itemId).toBeDefined();

      // Update to add dataType (migration scenario)
      await toprfSecureBackup.updateSecretDataItem({
        itemId: itemId as string,
        dataType: EncAccountDataType.PrimarySrp,
        authKeyPair: encKeyResult.authKeyPair,
      });

      const afterUpdate = await toprfSecureBackup.fetchAllSecretDataItems({
        decKey: encKeyResult.encKey,
        authKeyPair: encKeyResult.authKeyPair,
      });
      expect(afterUpdate).toHaveLength(1);
      expect(afterUpdate[0].dataType).toBe(EncAccountDataType.PrimarySrp);
      expect(afterUpdate[0].createdAt).toBe(originalCreatedAt);
    });
  });

  describe('batchUpdateSecretDataItems', function () {
    it('should batch update fields for existing items', async function () {
      const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        authConnectionId,
        userId,
      });
      const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: generateRandomPassword(),
        authConnectionId,
        userId,
      });

      // Add items without dataType (simulates old data that needs migration)
      await toprfSecureBackup.batchAddSecretDataItems({
        items: [
          { data: utf8ToBytes('data-1') },
          { data: utf8ToBytes('data-2') },
        ],
        encKey: encKeyResult.encKey,
        authKeyPair: encKeyResult.authKeyPair,
      });

      const beforeUpdate = await toprfSecureBackup.fetchAllSecretDataItems({
        decKey: encKeyResult.encKey,
        authKeyPair: encKeyResult.authKeyPair,
      });
      expect(beforeUpdate).toHaveLength(2);
      expect(beforeUpdate[0].dataType).toBeUndefined();
      expect(beforeUpdate[1].dataType).toBeUndefined();
      expect(beforeUpdate[0].createdAt).toBeDefined();
      expect(beforeUpdate[1].createdAt).toBeDefined();

      // Use actual itemIds returned from fetch (server generates/hashes them)
      const itemId1 = beforeUpdate[0].itemId as string;
      const itemId2 = beforeUpdate[1].itemId as string;
      const createdAt1 = beforeUpdate[0].createdAt;
      const createdAt2 = beforeUpdate[1].createdAt;
      expect(itemId1).toBeDefined();
      expect(itemId2).toBeDefined();

      // Update to add dataType (migration scenario)
      await toprfSecureBackup.batchUpdateSecretDataItems({
        updateItems: [
          { itemId: itemId1, dataType: EncAccountDataType.PrimarySrp },
          { itemId: itemId2, dataType: EncAccountDataType.ImportedSrp },
        ],
        authKeyPair: encKeyResult.authKeyPair,
      });

      const afterUpdate = await toprfSecureBackup.fetchAllSecretDataItems({
        decKey: encKeyResult.encKey,
        authKeyPair: encKeyResult.authKeyPair,
      });
      expect(afterUpdate).toHaveLength(2);
      const updatedItem1 = afterUpdate.find((item) => item.itemId === itemId1);
      const updatedItem2 = afterUpdate.find((item) => item.itemId === itemId2);
      expect(updatedItem1?.dataType).toBe(EncAccountDataType.PrimarySrp);
      expect(updatedItem2?.dataType).toBe(EncAccountDataType.ImportedSrp);
      expect(updatedItem1?.createdAt).toBe(createdAt1);
      expect(updatedItem2?.createdAt).toBe(createdAt2);
    });
  });

  describe('fetchAuthPubKey', function () {
    [undefined, 'torus-test-health-aggregate'].forEach((groupedConnId) => {
      it(`should return auth pub key ${fmtGroupedConnId(groupedConnId)}`, async function () {
        const { authConnectionId, userId, idToken, toprfSecureBackup } =
          setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });

        const password = generateRandomPassword();
        const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password,
          authConnectionId,
          userId,
        });

        const authPubKey = await toprfSecureBackup.fetchAuthPubKey({
          nodeAuthTokens: result.nodeAuthTokens,
          authConnectionId,
          userId,
          groupedAuthConnectionId: groupedConnId,
        });
        expect(authPubKey.authPubKey).toBeDefined();
        expect(authPubKey.authPubKey).toStrictEqual(
          encKeyResult.authKeyPair.pk,
        );
      });
    });
  });

  it('should throw error if user is not authenticated by enough nodes while creating enc key', async function () {
    const { authConnectionId, userId, idToken, toprfSecureBackup } = setup();

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      authConnectionId,
      userId,
    });
    const encKey = await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: generateRandomPassword(),
      authConnectionId,
      userId,
    });
    expect(encKey).toBeDefined();
    expect(encKey.authKeyPair).toBeDefined();
    expect(encKey.authKeyPair.sk).toBeDefined();
    expect(encKey.authKeyPair.pk).toBeDefined();
    expect(encKey.encKey).toBeDefined();

    await expect(
      toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens.slice(0, 2), // only 2 nodes are authenticated
        password: generateRandomPassword(),
        authConnectionId,
        userId,
      }),
    ).rejects.toBeDefined();
  });
});
