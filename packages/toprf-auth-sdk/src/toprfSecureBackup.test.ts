import { ToprfSecureBackup } from './toprfSecureBackup';
import { generateIdToken } from '../tests/testHelpers';

describe('toprf secure backup', function () {
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
});
