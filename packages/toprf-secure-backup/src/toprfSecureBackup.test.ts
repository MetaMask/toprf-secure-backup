import { TOPRFError } from '@metamask/auth-network-utils';
import { utf8ToBytes } from '@noble/ciphers/utils';

import { FIRST_KEY_INDEX } from './constants';
import * as resetRateLimitsModule from './resetRateLimits';
import { ToprfSecureBackup } from './toprfSecureBackup';
import {
  generateIdToken,
  generateRandomPassword,
  generateRandomVerifierId,
} from '../tests/testHelpers';

const EXISTNG_USER_VERIFIER_ID = 'test-verifier-id-existing-user';

// todo: add tests for the scenario when a existing user tries to create a new enc key.
describe('toprf secret backup', function () {
  it('should be able to authenticate user', async function () {
    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id-xyz-123';
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });
    expect(result).toBeDefined();
    expect(result.nodeAuthTokens).toBeDefined();
    expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
    expect(result.isNewUser).toBe(true);
  });

  it('should be able to create local enc key', async function () {
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });
    const password = generateRandomPassword();
    const encKey = toprfSecureBackup.createLocalEncKey({
      password,
    });
    expect(encKey).toBeDefined();
    expect(encKey.authKeyPair).toBeDefined();
    expect(encKey.authKeyPair.sk).toBeDefined();
    expect(encKey.authKeyPair.pk).toBeDefined();
    expect(encKey.encKey).toBeDefined();

    const encKey2 = toprfSecureBackup.createLocalEncKey({
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

    const encKey3 = toprfSecureBackup.createLocalEncKey({
      password,
    });
    expect(encKey3).toBeDefined();
    expect(encKey3.authKeyPair).toBeDefined();
    expect(encKey3.authKeyPair.sk).toBeDefined();
    expect(encKey3.authKeyPair.pk).toBeDefined();
    expect(encKey3.encKey).toBeDefined();

    expect(encKey3.authKeyPair.sk).not.toStrictEqual(encKey.authKeyPair.sk);
    expect(encKey3.encKey).not.toStrictEqual(encKey.encKey);

    const encKey4 = toprfSecureBackup.createLocalEncKey({
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

  it('should be able to create enc key', async function () {
    const verifier = 'torus-test-health';
    const verifierID = `test-verifier-id-${Math.random()}`;
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });
    expect(result.isNewUser).toBe(true);
    const encKey = await toprfSecureBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: generateRandomPassword(),
      verifier,
      verifierId: verifierID,
    });
    expect(encKey).toBeDefined();
    expect(encKey.authKeyPair).toBeDefined();
    expect(encKey.authKeyPair.sk).toBeDefined();
    expect(encKey.authKeyPair.pk).toBeDefined();
    expect(encKey.encKey).toBeDefined();
  });

  it('should be return isNewUser as false for existing user', async function () {
    const verifier = 'torus-test-health';
    const verifierID = EXISTNG_USER_VERIFIER_ID;
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });

    expect(result).toBeDefined();
    expect(result.nodeAuthTokens).toBeDefined();
    expect(result.nodeAuthTokens.length).toBeGreaterThan(0);
    expect(result.isNewUser).toBe(false);
  });

  it('should be able to recover enc key', async function () {
    const verifier = 'torus-test-health';
    const verifierID = `test-verifier-id-${Math.random()}`;
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });

    const password = generateRandomPassword();
    const encKey = await toprfSecureBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password,
      verifier,
      verifierId: verifierID,
    });

    const recoveredEncKey = await toprfSecureBackup.recoverEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password,
      verifier,
      verifierId: verifierID,
    });
    expect(recoveredEncKey).toBeDefined();
    expect(recoveredEncKey.authKeyPair).toBeDefined();
    expect(recoveredEncKey.authKeyPair.sk).toBeDefined();
    expect(recoveredEncKey.authKeyPair.pk).toBeDefined();
    expect(recoveredEncKey.encKey).toBeDefined();
    expect(recoveredEncKey.shareKeyIndex).toBeDefined();
    expect(await recoveredEncKey.rateLimitResetResult).toBeUndefined();

    expect(recoveredEncKey.authKeyPair.sk).toStrictEqual(encKey.authKeyPair.sk);
    expect(recoveredEncKey.encKey).toStrictEqual(encKey.encKey);
    expect(recoveredEncKey.authKeyPair.pk).toStrictEqual(encKey.authKeyPair.pk);
  });

  it('should throw error if user is not authenticated while creating enc key', async function () {
    const verifier = 'torus-test-health';
    const verifierID = `test-verifier-id-${Math.random()}`;
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    await expect(
      toprfSecureBackup.createEncKey({
        nodeAuthTokens: [],
        password: generateRandomPassword(),
        verifier,
        verifierId: verifierID,
      }),
    ).rejects.toBeDefined();
  });

  // somehow this test fails, need to check backend logs,.
  // eslint-disable-next-line jest/no-disabled-tests
  it.skip('should throw error if user is not authenticated by enough nodes while creating enc key', async function () {
    const verifier = 'torus-test-health';
    const verifierID = `test-verifier-id-${Math.random()}`;
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });
    const encKey = await toprfSecureBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: generateRandomPassword(),
      verifier,
      verifierId: verifierID,
    });
    expect(encKey).toBeDefined();
    expect(encKey.authKeyPair).toBeDefined();
    expect(encKey.authKeyPair.sk).toBeDefined();
    expect(encKey.authKeyPair.pk).toBeDefined();
    expect(encKey.encKey).toBeDefined();

    await expect(
      toprfSecureBackup.createEncKey({
        nodeAuthTokens: result.nodeAuthTokens.slice(0, 2),
        password: generateRandomPassword(),
        verifier,
        verifierId: verifierID,
      }),
    ).rejects.toBeDefined();
  });

  // TODO: Tests failed at the moment. We need to wait for the metadata-server to be deployed in all nodes.
  it('should be able to store secret data', async function () {
    const secretData = utf8ToBytes('test-secret-data');
    const verifier = 'torus-test-health';
    const verifierID = `test-verifier-id-${Math.random()}`;
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });
    const encKeyResult = await toprfSecureBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: generateRandomPassword(),
      verifier,
      verifierId: verifierID,
    });

    await toprfSecureBackup.addSecretDataItem({
      encKey: encKeyResult.encKey,
      secretData,
      authKeyPair: encKeyResult.authKeyPair,
    });

    const fetchedSecretData = await toprfSecureBackup.fetchAllSecretDataItems({
      decKey: encKeyResult.encKey,
      authKeyPair: encKeyResult.authKeyPair,
    });
    expect(fetchedSecretData).not.toBeNull();
    expect(fetchedSecretData?.[0]).toStrictEqual(secretData);
  });

  it('should be able to change encryption key', async function () {
    const secretData = utf8ToBytes('test-secret-data-for-key-change');
    const verifier = 'torus-test-health';
    const verifierID = `test-verifier-id-${Math.random()}`;
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecureBackup = new ToprfSecureBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecureBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });
    expect(result.nodeAuthTokens).toBeDefined();
    expect(result.nodeAuthTokens.length).toBeGreaterThan(0);

    const originalPassword = generateRandomPassword();
    const originalEncKeyResult = await toprfSecureBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: originalPassword,
      verifier,
      verifierId: verifierID,
    });

    await toprfSecureBackup.addSecretDataItem({
      encKey: originalEncKeyResult.encKey,
      secretData,
      authKeyPair: originalEncKeyResult.authKeyPair,
    });

    const originalSecretData = await toprfSecureBackup.fetchAllSecretDataItems({
      decKey: originalEncKeyResult.encKey,
      authKeyPair: originalEncKeyResult.authKeyPair,
    });
    expect(originalSecretData).not.toBeNull();
    expect(originalSecretData?.length).toBe(1);
    expect(originalSecretData?.[0]).toStrictEqual(secretData);

    // Recover the original key to get the shareKeyIndex
    const recoveredOriginalKey = await toprfSecureBackup.recoverEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: originalPassword,
      verifier,
      verifierId: verifierID,
    });

    expect(recoveredOriginalKey.shareKeyIndex).toBe(FIRST_KEY_INDEX);

    // Change to a new encryption key
    const newPassword = generateRandomPassword();
    const newEncKeyResult = await toprfSecureBackup.changeEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      verifier,
      verifierId: verifierID,
      oldEncKey: originalEncKeyResult.encKey,
      oldAuthKeyPair: originalEncKeyResult.authKeyPair,
      newPassword,
      newShareKeyIndex: recoveredOriginalKey.shareKeyIndex + 1,
    });
    expect(newEncKeyResult).toBeDefined();
    expect(newEncKeyResult.authKeyPair).toBeDefined();
    expect(newEncKeyResult.encKey).toBeDefined();

    const recoveredNewKey = await toprfSecureBackup.recoverEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: newPassword,
      verifier,
      verifierId: verifierID,
    });

    expect(recoveredNewKey.shareKeyIndex).toBe(
      recoveredOriginalKey.shareKeyIndex + 1,
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
  });

  it('should recover enc key even when rate limit reset fails', async function () {
    const mockResetRateLimits = jest
      .spyOn(resetRateLimitsModule, 'resetRateLimits')
      .mockImplementation(async () =>
        Promise.reject(TOPRFError.pwdInputRateLimitExceeded()),
      );

    try {
      const verifier = 'torus-test-health';
      const verifierID = generateRandomVerifierId();
      const idToken = generateIdToken(verifierID, 'ES256');
      const toprfSecureBackup = new ToprfSecureBackup({
        network: 'sapphire_devnet',
      });

      const result = await toprfSecureBackup.authenticate({
        idTokens: [idToken],
        verifier,
        verifierID,
      });

      const password = generateRandomPassword();
      const encKey = await toprfSecureBackup.createEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        verifier,
        verifierId: verifierID,
      });

      const recoveredKey = await toprfSecureBackup.recoverEncKey({
        nodeAuthTokens: result.nodeAuthTokens,
        password,
        verifier,
        verifierId: verifierID,
      });

      // Main functionality should work
      expect(recoveredKey.authKeyPair).toBeDefined();
      expect(recoveredKey.encKey).toBeDefined();
      expect(recoveredKey.authKeyPair.sk).toStrictEqual(encKey.authKeyPair.sk);
      expect(recoveredKey.encKey).toStrictEqual(encKey.encKey);
      expect(recoveredKey.shareKeyIndex).toBeDefined();

      // Rate limit reset should fail
      await expect(recoveredKey.rateLimitResetResult).rejects.toThrow(
        TOPRFError.pwdInputRateLimitExceeded(),
      );

      expect(mockResetRateLimits).toHaveBeenCalled();
    } finally {
      mockResetRateLimits.mockRestore();
    }
  });
});
