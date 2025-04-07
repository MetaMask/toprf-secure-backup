import { TOPRFError } from '@metamask/auth-network-utils';
import { utf8ToBytes } from '@noble/ciphers/utils';

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
