import { keccak256AndHexify } from '@metamask/auth-network-utils';
import { utf8ToBytes } from '@noble/ciphers/utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { FIRST_KEY_INDEX } from './constants';
import { TOPRFError, TOPRFErrorCode } from './errors';
import type { KeyPair } from './interfaces';
import { MetadataStore } from './metadata';
import * as resetRateLimitsModule from './resetRateLimits';
import { ToprfSecureBackup } from './toprfSecureBackup';
import {
  generateIdToken,
  generateRandomPassword,
  generateRandomVerifierId,
  sleep,
} from '../tests/testHelpers';

const EXISTING_USER_VERIFIER_ID = 'test-verifier-id-existing-user';

/**
 * Sets up the test environment.
 *
 * @param options - The options for the setup.
 * @param options.verifierId - The verifier id to be used for the test.
 * @param options.verifier - The verifier to be used for the test.
 * @returns The setup object.
 */
function setup(options?: { verifierId?: string; verifier?: string }): {
  verifier: string;
  verifierId: string;
  idToken: string;
  toprfSecureBackup: ToprfSecureBackup;
} {
  const verifier = options?.verifier ?? 'torus-test-health';
  const verifierId = options?.verifierId ?? generateRandomVerifierId();
  const idToken = generateIdToken(verifierId, 'ES256');
  const toprfSecureBackup = new ToprfSecureBackup({
    network: 'sapphire_devnet',
  });

  return { verifier, verifierId, idToken, toprfSecureBackup };
}

// TODO: add tests for the scenario when a existing user tries to create a new enc key.
describe('toprf secret backup', function () {
  describe('authenticate', function () {
    it('should be able to authenticate user', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });
      expect(result).toBeDefined();
      expect(result.nodeAuthTokens).toBeDefined();
      expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
      expect(result.isNewUser).toBe(true);
    });

    it('should be able to authenticate user with single id verifier', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup({
        verifier: 'torus-test-health-aggregate',
      });
      const hashedIdToken = keccak256AndHexify(utf8ToBytes(idToken)).slice(2);

      const result = await toprfSecureBackup.authenticate({
        idTokens: [hashedIdToken],
        verifier,
        verifierId,
        singleIdVerifierParams: {
          subVerifier: 'torus-test-health',
          subVerifierIdTokens: [idToken],
        },
      });

      expect(result).toBeDefined();
      expect(result.nodeAuthTokens).toBeDefined();
      expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
      expect(result.isNewUser).toBe(true);
    });

    it('should return isNewUser as false for existing user', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup({
        verifierId: EXISTING_USER_VERIFIER_ID,
      });

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      expect(result).toBeDefined();
      expect(result.nodeAuthTokens).toBeDefined();
      expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
      expect(result.isNewUser).toBe(false);
    });

    it('should throw error if unable to fetch node details', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

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
          verifier,
          verifierId,
        }),
      ).rejects.toThrow('Failed to get node details');

      expect(fndSpy).toHaveBeenCalled();
    });
  });

  describe('createAndPersistEncKey', function () {
    it('should be able to create local enc key', async function () {
      const { toprfSecureBackup } = setup();
      const password = generateRandomPassword();
      const encKey = toprfSecureBackup.createLocalKey({
        password,
      });
      expect(encKey).toBeDefined();
      expect(encKey.authKeyPair).toBeDefined();
      expect(encKey.authKeyPair.sk).toBeDefined();
      expect(encKey.authKeyPair.pk).toBeDefined();
      expect(encKey.encKey).toBeDefined();

      const encKey2 = toprfSecureBackup.createLocalKey({
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

      const encKey3 = toprfSecureBackup.createLocalKey({
        password,
      });
      expect(encKey3).toBeDefined();
      expect(encKey3.authKeyPair).toBeDefined();
      expect(encKey3.authKeyPair.sk).toBeDefined();
      expect(encKey3.authKeyPair.pk).toBeDefined();
      expect(encKey3.encKey).toBeDefined();

      expect(encKey3.authKeyPair.sk).not.toStrictEqual(encKey.authKeyPair.sk);
      expect(encKey3.encKey).not.toStrictEqual(encKey.encKey);

      const encKey4 = toprfSecureBackup.createLocalKey({
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

    it('should be able to create and persist enc key', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });
      expect(result.isNewUser).toBe(true);
      const encKey = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: generateRandomPassword(),
        verifier,
        verifierId,
      });
      expect(encKey).toBeDefined();
      expect(encKey.authKeyPair).toBeDefined();
      expect(encKey.authKeyPair.sk).toBeDefined();
      expect(encKey.authKeyPair.pk).toBeDefined();
      expect(encKey.encKey).toBeDefined();
    });

    it('should throw error if user is not authenticated while creating enc key', async function () {
      const { verifier, verifierId, toprfSecureBackup } = setup();

      await expect(
        toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: [],
          password: generateRandomPassword(),
          verifier,
          verifierId,
        }),
      ).rejects.toBeDefined();
    });

    it('should throw error if invalid auth tokens are provided', async function () {
      const { verifier, verifierId, toprfSecureBackup } = setup();
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
          verifier,
          verifierId,
        }),
      ).rejects.toThrow(TOPRFError.invalidAuthTokens());
    });
  });

  describe('recoverEncKey', function () {
    it('should be able to recover enc key', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const password = generateRandomPassword();
      const encKey = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        verifier,
        verifierId,
      });

      const recoveredEncKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        verifier,
        verifierId,
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
    });

    it('should recover enc key even when rate limit reset fails', async function () {
      const mockResetRateLimits = jest
        .spyOn(resetRateLimitsModule, 'resetRateLimits')
        .mockImplementation(async () =>
          Promise.reject(TOPRFError.pwdInputRateLimitExceeded()),
        );

      try {
        const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

        const result = await toprfSecureBackup.authenticate({
          idTokens: [idToken],
          verifier,
          verifierId,
        });

        const password = generateRandomPassword();
        const encKey = await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password,
          verifier,
          verifierId,
        });

        const recoveredKey = await toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password,
          verifier,
          verifierId,
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
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const password = generateRandomPassword();
      await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        verifier,
        verifierId,
      });

      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: 'INCORRECT_PASSWORD',
          verifier,
          verifierId,
        }),
      ).rejects.toThrow(TOPRFError.couldNotDeriveEncryptionKey());
    });

    it('should trigger rate limiting after multiple incorrect password attempts but allow correct password', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const authResult = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const correctPassword = generateRandomPassword();
      await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: authResult.nodeAuthTokens,
        password: correctPassword,
        verifier,
        verifierId,
      });

      const incorrectPassword = generateRandomPassword();

      // First 3 attempts with incorrect password should fail normally
      for (let i = 0; i < 3; i++) {
        await expect(
          toprfSecureBackup.recoverEncKey({
            nodeAuthTokens: authResult.nodeAuthTokens,
            password: incorrectPassword,
            verifier,
            verifierId,
          }),
        ).rejects.toThrow(TOPRFError.couldNotDeriveEncryptionKey());
      }

      // 4th attempt with incorrect password should trigger rate limiting
      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: authResult.nodeAuthTokens,
          password: incorrectPassword,
          verifier,
          verifierId,
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

      // Wait for the rate limit period
      await sleep(30000);

      // Attempt with the correct password should succeed and reset rate limit
      const recoveredKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: authResult.nodeAuthTokens,
        password: correctPassword,
        verifier,
        verifierId,
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
          verifier,
          verifierId,
        }),
      ).rejects.toThrow(TOPRFError.couldNotDeriveEncryptionKey());
    }, 40000);
  });

  describe('changeEncKey', function () {
    it('should be able to change encryption key and recover password', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-key-change');
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });
      expect(result.nodeAuthTokens).toBeDefined();
      expect(result.nodeAuthTokens.length).toBeGreaterThan(0);

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          verifier,
          verifierId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const originalSecretData =
        await toprfSecureBackup.fetchAllSecretDataItems({
          decKey: originalEncKeyResult.encKey,
          authKeyPair: originalEncKeyResult.authKeyPair,
        });
      expect(originalSecretData).not.toBeNull();
      expect(originalSecretData?.length).toBe(1);
      expect(originalSecretData?.[0]).toStrictEqual(secretData);

      // Recover the original key to get the keyShareIndex
      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        verifier,
        verifierId,
      });

      expect(recoveredOriginalKey.keyShareIndex).toBe(FIRST_KEY_INDEX);

      // Fetching password should fail, because password was not backed up yet.
      await expect(
        toprfSecureBackup.recoverPassword({
          targetPwPubKey: recoveredOriginalKey.authKeyPair.pk,
          curEncKey: originalEncKeyResult.encKey,
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
        verifier,
        verifierId,
        oldEncKey: originalEncKeyResult.encKey,
        oldAuthKeyPair: originalEncKeyResult.authKeyPair,
        oldPassword: originalPassword,
        newPassword,
        newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
      });
      expect(newEncKeyResult).toBeDefined();
      expect(newEncKeyResult.authKeyPair).toBeDefined();
      expect(newEncKeyResult.encKey).toBeDefined();

      const recoveredNewKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: newPassword,
        verifier,
        verifierId,
      });

      expect(recoveredNewKey.keyShareIndex).toBe(
        recoveredOriginalKey.keyShareIndex + 1,
      );

      // Verify the new key can access the data
      const newSecretData = await toprfSecureBackup.fetchAllSecretDataItems({
        decKey: recoveredNewKey.encKey,
        authKeyPair: recoveredNewKey.authKeyPair,
      });
      expect(newSecretData).not.toBeNull();
      expect(newSecretData?.length).toBe(1);
      expect(newSecretData?.[0]).toStrictEqual(secretData);

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

      // Verify that we can recover old pw.
      const recoveredPassword = await toprfSecureBackup.recoverPassword({
        targetPwPubKey: originalEncKeyResult.authKeyPair.pk,
        curEncKey: newEncKeyResult.encKey,
        curAuthKeyPair: newEncKeyResult.authKeyPair,
      });
      expect(recoveredPassword.password).toBe(originalPassword);

      // Change password again.
      const newPassword2 = generateRandomPassword();
      const newEncKeyResult2 = await toprfSecureBackup.changeEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        verifier,
        verifierId,
        oldEncKey: newEncKeyResult.encKey,
        oldAuthKeyPair: newEncKeyResult.authKeyPair,
        oldPassword: newPassword,
        newPassword: newPassword2,
        newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 2,
      });

      // Verify that we can recover old pw.
      const recoveredPassword2 = await toprfSecureBackup.recoverPassword({
        targetPwPubKey: originalEncKeyResult.authKeyPair.pk,
        curEncKey: newEncKeyResult2.encKey,
        curAuthKeyPair: newEncKeyResult2.authKeyPair,
      });
      expect(recoveredPassword2.password).toBe(originalPassword);

      // Verify that we can recover new pw.
      const recoveredPassword3 = await toprfSecureBackup.recoverPassword({
        targetPwPubKey: newEncKeyResult.authKeyPair.pk,
        curEncKey: newEncKeyResult2.encKey,
        curAuthKeyPair: newEncKeyResult2.authKeyPair,
      });
      expect(recoveredPassword3.password).toBe(newPassword);

      // Password recovery should fail when we limit the password chain length
      await expect(
        toprfSecureBackup.recoverPassword({
          targetPwPubKey: originalEncKeyResult.authKeyPair.pk,
          curEncKey: newEncKeyResult2.encKey,
          curAuthKeyPair: newEncKeyResult2.authKeyPair,
          maxPwChainLength: 1,
        }),
      ).rejects.toThrow(
        TOPRFError.couldNotFetchPassword(
          'Exceeded maximum password chain length',
        ),
      );
    });

    // The metadata lock has a 90 second expiry time and will auto-release after that period,
    // regardless of whether the key change succeeded or failed.
    // While changeEncKey() attempts to manually release the lock after a successful key change,
    // any failure to release the lock should not impact the overall key change operation.
    it('should not throw error when failed to released metadata lock', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-key-change');
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          verifier,
          verifierId,
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
        verifier,
        verifierId,
      });

      const releaseMetadataLockSpy = jest
        .spyOn(MetadataStore.prototype, 'releaseMetadataLock')
        .mockRejectedValue(new Error('Failed to release lock'));

      // Change to a new encryption key
      const newPassword = generateRandomPassword();
      const newEncKeyResult = await toprfSecureBackup.changeEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        verifier,
        verifierId,
        oldEncKey: originalEncKeyResult.encKey,
        oldAuthKeyPair: originalEncKeyResult.authKeyPair,
        oldPassword: originalPassword,
        newPassword,
        newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
      });
      expect(newEncKeyResult).toBeDefined();
      expect(newEncKeyResult.authKeyPair).toBeDefined();
      expect(newEncKeyResult.encKey).toBeDefined();

      expect(releaseMetadataLockSpy).toHaveBeenCalled();
    });

    it('should throw error when trying to change encryption key without existing data', async function () {
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      // Creating keys but intentionally not storing any secret data
      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          verifier,
          verifierId,
        });

      const newPassword = generateRandomPassword();

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          verifier,
          verifierId,
          oldEncKey: originalEncKeyResult.encKey,
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          oldPassword: originalPassword,
          newPassword,
          newKeyShareIndex: FIRST_KEY_INDEX + 1,
        }),
      ).rejects.toThrow('No existing data found to change key');
    });

    it('should throw error when metadata server fails during change encryption key', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-metadata-failure');
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      // Setup initial data
      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          verifier,
          verifierId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        verifier,
        verifierId,
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
            verifier,
            verifierId,
            oldEncKey: originalEncKeyResult.encKey,
            oldAuthKeyPair: originalEncKeyResult.authKeyPair,
            oldPassword: originalPassword,
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
          verifier,
          verifierId,
        }),
      ).rejects.toThrow('Could not derive encryption key');
    });

    it('should throw error when using incorrect authKeyPair during password change', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-incorrect-auth');
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          verifier,
          verifierId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        verifier,
        verifierId,
      });

      // Generate incorrect authKeyPair
      const differentPassword = generateRandomPassword();
      const incorrectKeyResult = toprfSecureBackup.createLocalKey({
        password: differentPassword,
      });

      const newPassword = generateRandomPassword();

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          verifier,
          verifierId,
          oldEncKey: originalEncKeyResult.encKey,
          oldAuthKeyPair: incorrectKeyResult.authKeyPair, // Using incorrect authKeyPair
          oldPassword: originalPassword,
          newPassword,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
        }),
      ).rejects.toThrow('No existing data found to change key');
    });

    it('should throw error when using incorrect encryption key during password change', async function () {
      const secretData = utf8ToBytes('test-secret-data-for-incorrect-enc-key');
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const originalPassword = generateRandomPassword();
      const originalEncKeyResult =
        await toprfSecureBackup.createAndPersistEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: originalPassword,
          verifier,
          verifierId,
        });

      await toprfSecureBackup.addSecretDataItem({
        encKey: originalEncKeyResult.encKey,
        secretData,
        authKeyPair: originalEncKeyResult.authKeyPair,
      });

      const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: originalPassword,
        verifier,
        verifierId,
      });

      // Generate incorrect encryption key
      const differentPassword = generateRandomPassword();
      const incorrectKeyResult = toprfSecureBackup.createLocalKey({
        password: differentPassword,
      });

      const newPassword = generateRandomPassword();

      await expect(
        toprfSecureBackup.changeEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          verifier,
          verifierId,
          oldEncKey: incorrectKeyResult.encKey, // Using incorrect encKey
          oldAuthKeyPair: originalEncKeyResult.authKeyPair,
          oldPassword: originalPassword,
          newPassword,
          newKeyShareIndex: recoveredOriginalKey.keyShareIndex + 1,
        }),
      ).rejects.toThrow(
        'failed to fetch metadata: failed to fetch metadata: aes/gcm: invalid ghash tag',
      );
    });
  });

  describe('addSecretDataItem', function () {
    it('should be able to store secret data', async function () {
      const secretData = utf8ToBytes('test-secret-data');
      const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });
      const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: generateRandomPassword(),
        verifier,
        verifierId,
      });

      await toprfSecureBackup.addSecretDataItem({
        encKey: encKeyResult.encKey,
        secretData,
        authKeyPair: encKeyResult.authKeyPair,
      });

      const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems(
        {
          decKey: encKeyResult.encKey,
          authKeyPair: encKeyResult.authKeyPair,
        },
      );
      expect(fetchedSecretData).not.toBeNull();
      expect(fetchedSecretData?.[0]).toStrictEqual(secretData);
    });
  });

  describe('batchAddSecretDataItems', function () {
    const secretDataArray = [
      utf8ToBytes('test-secret-data-1'),
      utf8ToBytes('test-secret-data-2'),
      utf8ToBytes('test-secret-data-3'),
    ];
    const password = generateRandomPassword();

    let toprfSecureBackup: ToprfSecureBackup;
    let encKey: Uint8Array;
    let authKeyPair: KeyPair;

    beforeEach(async function () {
      const {
        verifier,
        verifierId,
        idToken,
        toprfSecureBackup: _toprfSecureBackup,
      } = setup();
      toprfSecureBackup = _toprfSecureBackup;

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierId,
      });

      const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        verifier,
        verifierId,
      });
      encKey = encKeyResult.encKey;
      authKeyPair = encKeyResult.authKeyPair;
    });

    afterEach(function () {
      jest.restoreAllMocks();
    });

    it('should be able to store secret data in batch', async function () {
      await toprfSecureBackup.batchAddSecretDataItems({
        encKey,
        secretData: secretDataArray,
        authKeyPair,
      });

      const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems(
        {
          decKey: encKey,
          authKeyPair,
        },
      );

      // should have the same length as the secret data array
      expect(fetchedSecretData).toHaveLength(secretDataArray.length);

      // since all the secret items are added at once, they might have the same creation timestamp in the backend
      // so, we cannot assume that the fetched secret data is in the same order as the secret data array
      // hence we sort both arrays and then compare
      const sortedSecretDataArray = [...secretDataArray].sort();
      const sortedFetchedSecretData = [...fetchedSecretData].sort();
      expect(sortedFetchedSecretData).toStrictEqual(sortedSecretDataArray);
    });

    it('should throw an error when failed to acquire metadata lock', async function () {
      jest
        .spyOn(MetadataStore.prototype, 'acquireMetadataLock')
        .mockRejectedValue(new Error('Failed to acquire metadata lock'));

      await expect(
        toprfSecureBackup.batchAddSecretDataItems({
          encKey,
          secretData: secretDataArray,
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
        encKey,
        secretData: secretDataArray,
        authKeyPair,
      });

      const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems(
        {
          decKey: encKey,
          authKeyPair,
        },
      );

      // should have the same length as the secret data array
      expect(fetchedSecretData).toHaveLength(secretDataArray.length);

      // since all the secret items are added at once, they might have the same creation timestamp in the backend
      // so, we cannot assume that the fetched secret data is in the same order as the secret data array
      // hence we sort both arrays and then compare
      const sortedSecretDataArray = [...secretDataArray].sort();
      const sortedFetchedSecretData = [...fetchedSecretData].sort();
      expect(sortedFetchedSecretData).toStrictEqual(sortedSecretDataArray);
    });
  });

  it('should throw error if user is not authenticated by enough nodes while creating enc key', async function () {
    const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierId,
    });
    const encKey = await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: generateRandomPassword(),
      verifier,
      verifierId,
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
        verifier,
        verifierId,
      }),
    ).rejects.toBeDefined();
  });

  it('should return auth pub key', async function () {
    const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierId,
    });

    const password = generateRandomPassword();
    const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password,
      verifier,
      verifierId,
    });

    const authPubKey = await toprfSecureBackup.fetchAuthPubKey({
      nodeAuthTokens: result.nodeAuthTokens,
      verifier,
      verifierId,
    });
    expect(authPubKey.authPubKey).toBeDefined();
    expect(authPubKey.authPubKey).toStrictEqual(encKeyResult.authKeyPair.pk);
  });

  it('should trigger rate limiting after multiple incorrect password attempts', async function () {
    // Setup: Create user and password
    const { verifier, verifierId, idToken, toprfSecureBackup } = setup();

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierId,
    });

    const correctPassword = generateRandomPassword();
    const encKeyResult = await toprfSecureBackup.createAndPersistEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: correctPassword,
      verifier,
      verifierId,
    });

    // Create an account with incorrect password for testing
    expect(encKeyResult).toBeDefined();
    const incorrectPassword = generateRandomPassword();

    // First 3 attempts fail normally
    for (let i = 0; i < 3; i++) {
      await expect(
        toprfSecureBackup.recoverEncKey({
          nodeAuthTokens: result.nodeAuthTokens,
          password: incorrectPassword,
          verifier,
          verifierId,
        }),
      ).rejects.toThrow('Could not derive encryption key');
    }

    // 4th attempt triggers rate limiting
    await expect(
      toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password: incorrectPassword,
        verifier,
        verifierId,
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
  });
});
