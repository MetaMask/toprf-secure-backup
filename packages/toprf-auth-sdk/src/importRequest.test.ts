import { getSecp256K1Curve } from '@metamask/auth-network-utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateRequest } from './authenticateRequest';
import { commitmentRequest } from './commitmentRequest';
import { generateIdToken } from './testHelpers';

describe('authenticate request', function () {
  let nodeDetailManager: NodeDetailManager;
  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
      keyType: 'secp256k1',
      sigType: 'ecdsa-secp256k1',
    });
  });

  it('should create a authenticate request', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();
    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id';
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

    const authTokens = await authenticateRequest({
      idToken,
      verifier,
      verifierID,
      endpoints: torusNodeSSSEndpoints,
      commitmentSignatures: commitmentResults,
    });

    console.log('authTokens', authTokens);
    expect(authTokens).toBeDefined();
  });
});
