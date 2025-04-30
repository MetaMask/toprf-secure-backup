import { secp256k1 } from '@noble/curves/secp256k1';
import { toBytes } from '@noble/hashes/utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { TOPRFError } from './errors';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF, generateRandomScalar } from './oprf';
import { resetRateLimits } from './resetRateLimits';
import { changeKeyShares, storeKeyShares } from './storeSharesRequest';
import { recoverTOPRFSeed } from './toprfEvalRequest';
import { createNodeEndpointsMap } from './utils';
import { generateIdToken, generateRandomUserId } from '../tests/testHelpers';

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

    const authConnectionId = 'torus-test-health';
    const userId = generateRandomUserId();
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier: authConnectionId,
        verifierId: userId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
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
      authConnectionId,
      userId,
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
      authConnectionId,
      userId,
      authTokens: authTokensData,
      keyShareIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();
  });

  it('should be able to store shares even when 1 node is down', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = generateRandomUserId();
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier: authConnectionId,
        verifierId: userId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    const nodeEndpointsMap = createNodeEndpointsMap(
      torusNodeSSSEndpoints,
      torusIndexes,
    );

    const endpoints = [...torusNodeSSSEndpoints];
    endpoints[0] = endpoints[0].replace('/jrpc', '');

    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
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
      authConnectionId,
      userId,
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
      authConnectionId,
      userId,
      authTokens: authTokensData,
      keyShareIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();
  });

  it('should be able to change key after storing shares', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = generateRandomUserId();
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier: authConnectionId,
        verifierId: userId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
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
      authConnectionId,
      userId,
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
      authConnectionId,
      userId,
      authTokens: authTokensData,
      keyShareIndex: 1,
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

    // Verify that the original password works
    const {
      seed: originalRecoveredSeed,
      keyShareIndex: originalKeyShareIndex,
    } = await recoverTOPRFSeed({
      authTokens: authTokensData,
      nodeEndpointsMap: selectedEndpointsMap,
      authConnectionId,
      userId,
      userInput: originalPasswordBytes,
    });

    expect(originalRecoveredSeed).toBeDefined();
    expect(originalRecoveredSeed.length).toBeGreaterThan(0);
    expect(originalKeyShareIndex).toBeDefined();
    expect(originalKeyShareIndex).toBeGreaterThan(0);

    // Verify that the new password doesn't work
    await expect(
      recoverTOPRFSeed({
        authTokens: authTokensData,
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        userId,
        userInput: newPasswordBytes,
      }),
    ).rejects.toThrow('Could not derive encryption key');

    // Reset the rate limit
    await resetRateLimits({
      authTokens: authTokensData,
      nodeEndpointsMap: selectedEndpointsMap,
      authConnectionId,
      userId,
      authPrivKey: originalAuthKeyPair.sk,
    });

    // Change the key
    const keyChangeResponse = await changeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      authConnectionId,
      userId,
      authTokens: authTokensData,
      oldAuthPrivKey: originalAuthKeyPair.sk,
      keyShareIndex: 2,
      newOprfKey,
      newAuthPubKey: newAuthKeyPair.pk,
    });

    expect(keyChangeResponse).toBeDefined();
    expect(keyChangeResponse.error).toBeUndefined();

    // Verify that the original password doesn't work
    await expect(
      recoverTOPRFSeed({
        authTokens: authTokensData,
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        userId,
        userInput: originalPasswordBytes,
      }),
    ).rejects.toThrow('Could not derive encryption key');

    // Verify that the new password works
    const { seed: newRecoveredSeed, keyShareIndex: newKeyShareIndex } =
      await recoverTOPRFSeed({
        authTokens: authTokensData,
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        userId,
        userInput: newPasswordBytes,
      });

    expect(newRecoveredSeed).toBeDefined();
    expect(newRecoveredSeed.length).toBeGreaterThan(0);
    expect(newKeyShareIndex).toBeDefined();
    expect(newKeyShareIndex).toBeGreaterThan(0);
  });

  it('should fail when trying to change key before storing shares', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = generateRandomUserId();
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier: authConnectionId,
        verifierId: userId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
    });

    const nodeEndpointsMap = createNodeEndpointsMap(
      torusNodeSSSEndpoints,
      torusIndexes,
    );

    const selectedEndpointsMap = commitmentResults.reduce<
      Record<number, string>
    >((acc, result) => {
      acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
      return acc;
    }, {});

    const { authTokensData } = await authenticateUser({
      idToken,
      authConnectionId,
      userId,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });

    expect(authTokensData).toBeDefined();

    const originalPasswordBytes = toBytes('original-password');
    const oprfKey = generateRandomScalar();
    const originalSeed = OPRF.localEval(oprfKey, originalPasswordBytes);
    const originalAuthKeyPair = deriveAuthenticationKeyPair(originalSeed);

    const newPasswordBytes = toBytes('new-password');
    const newOprfKey = generateRandomScalar();
    const newSeed = OPRF.localEval(newOprfKey, newPasswordBytes);
    const newAuthKeyPair = deriveAuthenticationKeyPair(newSeed);

    // Attempt to change key before storing shares, which should fail
    await expect(
      changeKeyShares({
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        userId,
        authTokens: authTokensData,
        oldAuthPrivKey: originalAuthKeyPair.sk,
        keyShareIndex: 2,
        newOprfKey,
        newAuthPubKey: newAuthKeyPair.pk,
      }),
    ).rejects.toThrow(
      TOPRFError.jsonRpcError(
        'Regular import flow invalid - KeyChangeProof should be nil for regular import',
      ),
    );
  });

  it('should fail when trying to change to a lower key index', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = generateRandomUserId();
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier: authConnectionId,
        verifierId: userId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);

    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: torusNodeSSSEndpoints,
    });

    const nodeEndpointsMap = createNodeEndpointsMap(
      torusNodeSSSEndpoints,
      torusIndexes,
    );

    const selectedEndpointsMap = commitmentResults.reduce<
      Record<number, string>
    >((acc, result) => {
      acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
      return acc;
    }, {});

    const { authTokensData } = await authenticateUser({
      idToken,
      authConnectionId,
      userId,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });

    expect(authTokensData).toBeDefined();

    const originalPasswordBytes = toBytes('original-password');
    const oprfKey = generateRandomScalar();
    const originalSeed = OPRF.localEval(oprfKey, originalPasswordBytes);
    const originalAuthKeyPair = deriveAuthenticationKeyPair(originalSeed);

    // Use a higher initial key index
    const initialKeyIndex = 2;

    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      authConnectionId,
      userId,
      authTokens: authTokensData,
      keyShareIndex: initialKeyIndex,
      oprfKey,
      authPubKey: originalAuthKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();

    const newPasswordBytes = toBytes('new-password');
    const newOprfKey = generateRandomScalar();
    const newSeed = OPRF.localEval(newOprfKey, newPasswordBytes);
    const newAuthKeyPair = deriveAuthenticationKeyPair(newSeed);

    // Try to change key with a lower key index
    const lowerKeyIndex = 1;

    await expect(
      changeKeyShares({
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        userId,
        authTokens: authTokensData,
        keyShareIndex: lowerKeyIndex,
        newOprfKey,
        newAuthPubKey: newAuthKeyPair.pk,
        oldAuthPrivKey: originalAuthKeyPair.sk,
      }),
    ).rejects.toThrow(
      TOPRFError.jsonRpcError('Failed to validate key share index'),
    );
  });
});
