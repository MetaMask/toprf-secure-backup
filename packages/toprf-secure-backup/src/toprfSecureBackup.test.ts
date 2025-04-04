import { ToprfSecureBackup } from './toprfSecureBackup';
import { generateIdToken } from '../tests/testHelpers';

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

    // as this user doesn't have any enc key yet.
    expect(result.hasValidEncKey).toBe(false);
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
    const encKey = await toprfSecureBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: 'test-password',
      verifier,
      verifierId: verifierID,
    });
    expect(encKey).toBeDefined();
    expect(encKey.authKeyPair).toBeDefined();
    expect(encKey.authKeyPair.sk).toBeDefined();
    expect(encKey.authKeyPair.pk).toBeDefined();
    expect(encKey.encKey).toBeDefined();
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
        password: 'test-password',
        verifier,
        verifierId: verifierID,
      }),
    ).rejects.toBeDefined();
  });

  it('should throw error if user is not authenticated by enough nodes while creating enc key', async function () {
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

    await expect(
      toprfSecureBackup.createEncKey({
        nodeAuthTokens: result.nodeAuthTokens.slice(0, 2),
        password: 'test-password',
        verifier,
        verifierId: verifierID,
      }),
    ).rejects.toBeDefined();
  });
});
