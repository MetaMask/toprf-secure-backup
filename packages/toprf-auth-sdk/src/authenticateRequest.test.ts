import { getSecp256K1Curve } from '@metamask/auth-network-utils';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitmentRequest';
import { NODE_URLS } from './constants';
import { generateIdToken } from './testHelpers';

describe('authenticate request', function () {
  it('should authenticate user and validate responses', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();

    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id';
    const idToken = generateIdToken(verifierID, 'ES256');
    const sessionPubKeyX = pubPoint.getX().toString('hex');
    const sessionPubKeyY = pubPoint.getY().toString('hex');

    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: NODE_URLS,
    });

    const sessionPrivateKey = keyPair.getPrivate().toString('hex');
    const authenticateResults = await authenticateUser({
      idToken,
      verifier,
      verifierID,
      sessionPrivateKey,
      endpoints: NODE_URLS,
      commitmentSignatures: commitmentResults,
    });

    expect(authenticateResults).toBeDefined();
    expect(authenticateResults.length).toBeGreaterThan(0);

    authenticateResults.forEach((result) => {
      expect(result.authToken).toBeDefined();
      expect(result.nodeIndex).toBeDefined();
      expect(result.nodePubKey).toBeDefined();
      expect(result.pubKey).toBeDefined();
      expect(result.keyIndex).toBeDefined();
    });
  });
});
