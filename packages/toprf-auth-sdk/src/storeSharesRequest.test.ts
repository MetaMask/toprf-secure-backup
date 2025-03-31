import { getSecp256K1Curve } from '@metamask/auth-network-utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitmentRequest } from './commitmentRequest';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF, generateRandomScalar } from './oprf';
import { storeKeyShares } from './storeSharesRequest';
import { generateIdToken } from './testHelpers';

describe('store shares request', function () {
  let nodeDetailManager: NodeDetailManager;
  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
      keyType: 'secp256k1',
      sigType: 'ecdsa-secp256k1',
    });
  });

  it('should be able to store shares', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();
    const verifier = 'torus-test-health';
    // generate a random verifierID string
    const verifierID = `test-verifier-id-${Math.random()}`;
    const { torusNodeSSSEndpoints, torusIndexes, torusNodePub } =
      await nodeDetailManager.getNodeDetails({
        verifier,
        verifierId: verifierID,
      });

    if (!torusNodeSSSEndpoints || !torusIndexes || !torusNodePub) {
      throw new Error('Failed to get node details');
    }

    const idToken = generateIdToken(verifierID, 'ES256');
    const sessionPubKeyX = pubPoint.getX().toString('hex');
    const sessionPubKeyY = pubPoint.getY().toString('hex');

    const commitmentResults = await commitmentRequest({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
      indexes: torusIndexes,
    });

    const authTokens = await authenticateUser({
      idToken,
      verifier,
      verifierID,
      sessionPrivateKey: keyPair.getPrivate().toString('hex'),
      endpoints: torusNodeSSSEndpoints,
      commitmentSignatures: commitmentResults,
    });

    expect(authTokens).toBeDefined();
    const randomScalar = generateRandomScalar();
    const seed = OPRF.localEval(
      randomScalar,
      new TextEncoder().encode('abcdefgh'),
    );
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    const storeSharesResponse = await storeKeyShares(torusNodeSSSEndpoints, {
      nodeIndexes: torusIndexes,
      nodePubkeys: torusNodePub,
      verifier,
      verifierId: verifierID,
      authTokens: authTokens.map((tokenData) => ({
        authToken: tokenData.authToken,
        nodeIndex: tokenData.nodeIndex,
        nodePubKey: tokenData.nodePubKey,
      })),
      keyIndex: 1,
      oprfKey: randomScalar,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();
  });
});
