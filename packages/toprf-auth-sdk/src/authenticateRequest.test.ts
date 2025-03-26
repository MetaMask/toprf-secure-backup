import { getSecp256K1Curve } from '@metamask/auth-network-utils';

import {
  createAuthenticateRequest,
  createAuthenticateRequestParams,
} from './authenticateRequest';
import { commitmentRequest } from './commitmentRequest';
import { NODE_URLS } from './constants';
import { generateIdToken } from './testHelpers';

describe('authenticate request', function () {
  it('should create a authenticate request', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();

    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id';
    const idToken = generateIdToken(verifierID, 'ES256');
    const sessionPubKeyX = pubPoint.getX().toString('hex');
    const sessionPubKeyY = pubPoint.getY().toString('hex');

    const commitmentResults = await commitmentRequest({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: NODE_URLS,
      indexes: [1, 2, 3, 4, 5],
    });

    const authParams = createAuthenticateRequestParams(
      idToken,
      verifier,
      verifierID,
      commitmentResults,
    );
    const authJRPCRequest = await createAuthenticateRequest(
      NODE_URLS[0],
      authParams,
    );
    expect(authJRPCRequest).toBeDefined();
    expect(authJRPCRequest.jsonrpc).toBe('2.0');
    expect(authJRPCRequest.id).toBeDefined();
    expect(authJRPCRequest.result).toBeDefined();
    expect(authJRPCRequest.result?.authToken).toBeDefined();
    expect(authJRPCRequest.result?.nodeIndex).toBeDefined();
    expect(authJRPCRequest.result?.pubKey).toBeDefined();
    expect(authJRPCRequest.result?.keyIndex).toBeDefined();
  });
});
