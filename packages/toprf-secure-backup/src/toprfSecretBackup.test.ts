import { ToprfSecretBackup } from './toprfSecretBackup';
import { generateIdToken } from '../tests/testHelpers';

describe('toprf secret backup', function () {
  it('should be able to authenticate user', async function () {
    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id-xyz-123';
    const idToken = generateIdToken(verifierID, 'ES256');
    const toprfSecretBackup = new ToprfSecretBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecretBackup.authenticate({
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
    const toprfSecretBackup = new ToprfSecretBackup({
      network: 'sapphire_devnet',
    });

    const result = await toprfSecretBackup.authenticate({
      idTokens: [idToken],
      verifier,
      verifierID,
    });
    const encKey = await toprfSecretBackup.createEncKey({
      nodeAuthTokens: result.nodeAuthTokens,
      password: 'test-password',
      verifier,
      verifierId: verifierID,
    });
    expect(encKey).toBeDefined();
    expect(encKey.authKeyPair).toBeDefined();
    expect(encKey.authKeyPair.privKey).toBeDefined();
    expect(encKey.authKeyPair.pubKey).toBeDefined();
    expect(encKey.encKey).toBeDefined();
  });
});
