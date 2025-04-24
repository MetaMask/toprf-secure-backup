import { keccak256AndHexify } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import {
  authenticateUser,
  createAuthResponseHandler,
} from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { AUTHENTICATION_THRESHOLD } from './constants';
import { TOPRFError } from './errors';
import type { AuthJRPCResponse } from './jrpcInterfaces';
import { createNodeEndpointsMap } from './utils';
import {
  generateIdToken,
  generateRandomVerifierId,
} from '../tests/testHelpers';

describe('authenticate request', function () {
  let nodeDetailManager: NodeDetailManager;
  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
    });
  });

  it('should be able to send a authenticate request', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const verifier = 'torus-test-health';
    const verifierId = 'test-verifier-id';
    const idToken = generateIdToken(verifierId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier,
        verifierId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }
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

    const selectedEndpointsMap = commitmentResults.reduce<
      Record<number, string>
    >((acc, result) => {
      acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
      return acc;
    }, {});
    const { authTokensData } = await authenticateUser({
      idToken,
      verifier,
      verifierId,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });
    expect(authTokensData).toBeDefined();
    expect(authTokensData.length).toBeGreaterThanOrEqual(3);
  });

  it('should to send an authentication request for a new user with single id verifier', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const verifier = 'torus-test-health-aggregate';
    const verifierId = generateRandomVerifierId();
    const idToken = generateIdToken(verifierId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier,
        verifierId,
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }
    const hashedIdToken = keccak256AndHexify(
      Buffer.from(idToken, 'utf8'),
    ).slice(2);

    const commitmentResults = await commitIdToken({
      idToken: hashedIdToken,
      verifier,
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

    const { authTokensData, isNewUser } = await authenticateUser({
      idToken: hashedIdToken,
      verifier,
      verifierId,
      sessionPrivateKey: privKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
      singleIdVerifierParams: {
        subVerifier: 'torus-test-health',
        subVerifierIdTokens: [idToken],
      },
    });
    expect(authTokensData).toBeDefined();
    expect(authTokensData.length).toBeGreaterThanOrEqual(3);
    expect(isNewUser).toBe(true);
  });
});

/**
 * Helper function to create mock auth responses.
 *
 * @param nodeIndex - The node index to use.
 * @param pubKey - Optional public key (empty string for new user).
 * @param keyIndex - Optional key index.
 * @returns A mock auth response.
 */
const mockAuthResponse = (
  nodeIndex: number,
  pubKey = '04existingPubKey', // Default to existing user
  keyIndex = 1,
): AuthJRPCResponse => ({
  jsonrpc: '2.0',
  id: 1,
  result: {
    nodeIndex,
    authToken: `mockAuthToken${nodeIndex}`,
    nodePubKey: `mockNodePubKey${nodeIndex}`,
    pubKey,
    keyIndex,
  },
});

describe('createAuthResponseHandler', () => {
  const threshold = AUTHENTICATION_THRESHOLD;
  const bufferWaitTime = 1000;

  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should return undefined if threshold not met and not all settled', async () => {
    const results = Array.from({ length: threshold - 1 }, (_, i) =>
      mockAuthResponse(i),
    );
    results.push(undefined as any, undefined as any);
    const handler = createAuthResponseHandler(results, false);
    expect(await handler()).toBeUndefined();
  });

  it('should return undefined if threshold met but buffer not elapsed and not all settled', async () => {
    const results = Array.from({ length: threshold }, (_, i) =>
      mockAuthResponse(i),
    );
    results.push(undefined as any);
    const handler = createAuthResponseHandler(results, false);

    expect(await handler()).toBeUndefined();
    await jest.advanceTimersByTimeAsync(bufferWaitTime / 2);
    expect(await handler()).toBeUndefined();
  });

  it('should return results if threshold met and buffer has elapsed (existing user)', async () => {
    const results = Array.from({ length: threshold }, (_, i) =>
      mockAuthResponse(i, '04existingPubKey'),
    );
    results.push(undefined as any);
    const handler = createAuthResponseHandler(results, false);

    expect(await handler()).toBeUndefined();
    await jest.advanceTimersByTimeAsync(bufferWaitTime + 50);

    const finalResult = await handler();
    expect(finalResult).toBeDefined();
    expect(finalResult?.authRequestResults).toHaveLength(threshold);
    expect(finalResult?.isNewUser).toBe(false);
  });

  it('should return results if threshold met and buffer has elapsed (new user)', async () => {
    const results = Array.from({ length: threshold }, (_, i) =>
      mockAuthResponse(i, ''),
    );
    results.push(undefined as any);
    const handler = createAuthResponseHandler(results, false);

    expect(await handler()).toBeUndefined();
    await jest.advanceTimersByTimeAsync(bufferWaitTime + 50);

    const finalResult = await handler();
    expect(finalResult).toBeDefined();
    expect(finalResult?.authRequestResults).toHaveLength(threshold);
    expect(finalResult?.isNewUser).toBe(true);
  });

  it('should return results if threshold met and all have settled (before buffer)', async () => {
    const results = Array.from({ length: threshold + 1 }, (_, i) =>
      mockAuthResponse(i),
    );
    const handler = createAuthResponseHandler(results, true);

    const finalResult = await handler();
    expect(finalResult).toBeDefined();
    expect(finalResult?.authRequestResults).toHaveLength(threshold + 1);
    expect(finalResult?.isNewUser).toBe(false);
  });

  it('should throw TOPRFError if threshold not met when all settled', async () => {
    const results = Array.from({ length: threshold - 1 }, (_, i) =>
      mockAuthResponse(i),
    );
    const handler = createAuthResponseHandler(results, true);

    await expect(handler()).rejects.toBeInstanceOf(TOPRFError);
    await expect(handler()).rejects.toThrow(
      `Authentication threshold not met after all requests processed. Expected: ${threshold}, got: ${threshold - 1}`,
    );
  });

  it('should throw TOPRFError if threshold met but data is inconsistent when finalized', async () => {
    const results: AuthJRPCResponse[] = [];
    for (let i = 0; i < threshold; i++) {
      results.push(mockAuthResponse(i, `inconsistentPubKey_${i}`, i + 1));
    }
    const handler = createAuthResponseHandler(results, true);

    await expect(handler()).rejects.toBeInstanceOf(TOPRFError);
    await expect(handler()).rejects.toThrow(
      /Authentication threshold met, but pubKey\/keyIndex data inconsistent:/u,
    );
  });

  it('should track thresholdMetTime correctly across calls', async () => {
    const resultsMeetThreshold = Array.from({ length: threshold }, (_, i) =>
      mockAuthResponse(i),
    );
    resultsMeetThreshold.push(undefined as any);
    const handler = createAuthResponseHandler(resultsMeetThreshold, false);

    expect(await handler()).toBeUndefined();
    const timeAfterFirstCall = Date.now();

    await jest.advanceTimersByTimeAsync(bufferWaitTime / 2);
    const timeAfterAdvance = Date.now();

    expect(await handler()).toBeUndefined();

    const remainingBuffer =
      bufferWaitTime - (timeAfterAdvance - timeAfterFirstCall);
    await jest.advanceTimersByTimeAsync(remainingBuffer + 50);

    const finalResult = await handler();
    expect(finalResult).toBeDefined();
    expect(finalResult?.authRequestResults).toHaveLength(threshold);
  });
});
