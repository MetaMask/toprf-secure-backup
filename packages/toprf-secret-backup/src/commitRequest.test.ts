import { getSecp256K1Curve } from '@metamask/auth-network-utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { commitIdToken } from './commitRequest';
import { generateIdToken } from '../tests/testHelpers';

describe('commitment request', function () {
  let nodeDetailManager: NodeDetailManager;
  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
      keyType: 'secp256k1',
      sigType: 'ecdsa-secp256k1',
    });
  });
  it('should create a commitment request', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();

    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id';
    const idToken = generateIdToken(verifierID, 'ES256');
    const sessionPubKeyX = pubPoint.getX().toString('hex');
    const sessionPubKeyY = pubPoint.getY().toString('hex');
    const { torusNodeSSSEndpoints, torusIndexes, torusNodePub } =
      await nodeDetailManager.getNodeDetails({
        verifier,
        verifierId: verifierID,
      });

    if (!torusNodeSSSEndpoints || !torusIndexes || !torusNodePub) {
      throw new Error('Failed to get node details');
    }
    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
    });
    expect(commitmentResults).toBeDefined();
    expect(commitmentResults.length).toBeGreaterThanOrEqual(4);
    expect(commitmentResults[0].signature).toBeDefined();
    expect(commitmentResults[0].data).toBeDefined();
    expect(commitmentResults[0].nodePubX).toBeDefined();
    expect(commitmentResults[0].nodePubY).toBeDefined();
    expect(commitmentResults[0].nodeIndex).toBe('1');
  });
});
