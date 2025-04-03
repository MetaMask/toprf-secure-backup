import { getSecp256K1Curve } from '@metamask/auth-network-utils';
import { toBytes } from '@noble/hashes/utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';
import { sha256 } from 'ethereum-cryptography/sha256';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF, generateRandomScalar } from './oprf';
import { storeKeyShares } from './storeSharesRequest';
import { generateIdToken } from '../tests/testHelpers';

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

    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
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
    const passwordBytes = toBytes('test-input');
    const hashedInput = sha256(passwordBytes);
    const oprfKey = generateRandomScalar();
    const seed = OPRF.localEval(oprfKey, hashedInput);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    const nodeEndpointsMap = torusIndexes.reduce<Record<number, string>>(
      (acc, index) => {
        acc[index] = torusNodeSSSEndpoints[index - 1];
        return acc;
      },
      {},
    );

    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap,
      verifier,
      verifierId: verifierID,
      authTokens,
      keyIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();
  });
});
