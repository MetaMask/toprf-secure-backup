import { secp256k1 } from '@noble/curves/secp256k1';
import { toBytes } from '@noble/hashes/utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF, generateRandomScalar } from './oprf';
import { changeKey, storeKeyShares } from './storeSharesRequest';
import { createNodeEndpointsMap } from './utils';
import { generateIdToken } from '../tests/testHelpers';

describe('secure backup operations', function () {
  let nodeDetailManager: NodeDetailManager;
  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
    });
  });

  it('should be able to store shares for a new user', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

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
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
    });

    const nodeEndpointsMap = createNodeEndpointsMap(
      torusNodeSSSEndpoints,
      torusIndexes,
    );

    // use only the node indexes that returned valid commitment responses
    const selectedEndpointsMap = commitmentResults.reduce<
      Record<number, string>
    >((acc, result) => {
      acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
      return acc;
    }, {});

    const { authTokensData } = await authenticateUser({
      idToken,
      verifier,
      verifierID,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });
    expect(authTokensData).toBeDefined();
    const passwordBytes = toBytes('test-input');
    const oprfKey = generateRandomScalar();
    const seed = OPRF.localEval(oprfKey, passwordBytes);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId: verifierID,
      authTokens: authTokensData,
      keyIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();
  });

  it('should be able to store shares even when 1 node is down', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

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

    const nodeEndpointsMap = createNodeEndpointsMap(
      torusNodeSSSEndpoints,
      torusIndexes,
    );

    const endpoints = [...torusNodeSSSEndpoints];
    endpoints[0] = endpoints[0].replace('/jrpc', '');

    const idToken = generateIdToken(verifierID, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints,
    });

    // use only the node indexes that returned valid commitment responses
    const selectedEndpointsMap = commitmentResults.reduce<
      Record<number, string>
    >((acc, result) => {
      acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
      return acc;
    }, {});
    const { authTokensData } = await authenticateUser({
      idToken,
      verifier,
      verifierID,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });

    expect(authTokensData).toBeDefined();
    const passwordBytes = toBytes('test-input');
    const oprfKey = generateRandomScalar();
    const seed = OPRF.localEval(oprfKey, passwordBytes);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId: verifierID,
      authTokens: authTokensData,
      keyIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();
  });

  it('should be able to change key after storing shares', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

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
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
    });

    const nodeEndpointsMap = createNodeEndpointsMap(
      torusNodeSSSEndpoints,
      torusIndexes,
    );

    // use only the node indexes that returned valid commitment responses
    const selectedEndpointsMap = commitmentResults.reduce<
      Record<number, string>
    >((acc, result) => {
      acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
      return acc;
    }, {});

    const { authTokensData } = await authenticateUser({
      idToken,
      verifier,
      verifierID,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });

    expect(authTokensData).toBeDefined();

    // Original password setup
    const originalPasswordBytes = toBytes('original-password');
    const oprfKey = generateRandomScalar();
    const originalSeed = OPRF.localEval(oprfKey, originalPasswordBytes);
    const originalAuthKeyPair = deriveAuthenticationKeyPair(originalSeed);

    // Store shares with original password
    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId: verifierID,
      authTokens: authTokensData,
      keyIndex: 1,
      oprfKey,
      authPubKey: originalAuthKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();

    // Key change flow - new password setup
    const newPasswordBytes = toBytes('new-password');
    const newOprfKey = generateRandomScalar();
    const newSeed = OPRF.localEval(newOprfKey, newPasswordBytes);
    const newAuthKeyPair = deriveAuthenticationKeyPair(newSeed);

    const keyChangeResponse = await changeKey({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId: verifierID,
      authTokens: authTokensData,
      oldAuthPrivKey: originalAuthKeyPair.sk,
      keyIndex: 2,
      newOprfKey,
      newAuthPubKey: newAuthKeyPair.pk,
    });

    expect(keyChangeResponse).toBeDefined();
    expect(keyChangeResponse.error).toBeUndefined();
  });
});
