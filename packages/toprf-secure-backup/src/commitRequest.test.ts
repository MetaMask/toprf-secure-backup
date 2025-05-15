import { secp256k1 } from '@noble/curves/secp256k1';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import {
  commitIdToken,
  createHandleCommitmentResponses,
} from './commitRequest';
import { COMMIT_RESPONSE_THRESHOLD } from './constants';
import { TOPRFError } from './errors';
import type { CommitmentJRPCResponse } from './jrpcInterfaces';
import { generateIdToken } from '../tests/testHelpers';

describe('commitment request', function () {
  let nodeDetailManager: NodeDetailManager;

  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
    });
  });

  it('should create a commitment request', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = 'test-user-id';
    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);
    const { torusNodeSSSEndpoints } = await nodeDetailManager.getNodeDetails({
      verifier: authConnectionId,
      verifierId: userId,
    });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }
    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
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
    expect(commitmentResults[0].nodeIndex).toBeDefined();
  });

  it('should work when only 1 node is down', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = 'test-user-id';
    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);
    const { torusNodeSSSEndpoints } = await nodeDetailManager.getNodeDetails({
      verifier: authConnectionId,
      verifierId: userId,
    });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    const endpoints = [...torusNodeSSSEndpoints];
    endpoints[0] = 'https://invalid-endpoint';

    const commitmentResults = await commitIdToken({
      idToken,
      authConnectionId,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints,
    });
    expect(commitmentResults).toBeDefined();
    expect(commitmentResults.length).toBeGreaterThanOrEqual(4);
    expect(commitmentResults[0].signature).toBeDefined();
    expect(commitmentResults[0].data).toBeDefined();
    expect(commitmentResults[0].nodePubX).toBeDefined();
    expect(commitmentResults[0].nodePubY).toBeDefined();
    expect(commitmentResults[0].nodeIndex).toBeDefined();
  });

  it('should throw an error if more than 1 node is down', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const authConnectionId = 'torus-test-health';
    const userId = 'test-user-id';
    const idToken = generateIdToken(userId, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);
    const { torusNodeSSSEndpoints } = await nodeDetailManager.getNodeDetails({
      verifier: authConnectionId,
      verifierId: userId,
    });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }
    const endpoints = [...torusNodeSSSEndpoints];
    // node endpoints without path, so that test won't get stuck
    endpoints[0] = endpoints[0].replace('/jrpc', '');
    endpoints[1] = endpoints[1].replace('/jrpc', '');
    endpoints[2] = endpoints[1].replace('/jrpc', '');
    endpoints[3] = endpoints[1].replace('/jrpc', '');
    endpoints[4] = endpoints[1].replace('/jrpc', '');

    await expect(
      commitIdToken({
        idToken,
        authConnectionId,
        sessionPubKeyX,
        sessionPubKeyY,
        endpoints,
      }),
    ).rejects.toBeDefined();
  });
});

/**
 * Helper function to create mock commitment responses.
 *
 * @param nodeIndex - The node index to use.
 * @returns A mock commitment response.
 */
const mockCommitResponse = (nodeIndex: number): CommitmentJRPCResponse => ({
  jsonrpc: '2.0',
  id: 1,
  result: {
    nodeIndex,
    signature: `mockSignature${nodeIndex}`,
    nodePubX: `mockNodePubX${nodeIndex}`,
    nodePubY: `mockNodePubY${nodeIndex}`,
    data: `mockData${nodeIndex}`,
  },
});

describe('createHandleCommitmentResponses', () => {
  const threshold = COMMIT_RESPONSE_THRESHOLD;
  const bufferWaitTime = 1000;

  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should return undefined if threshold not met and not all settled', async () => {
    const results = Array.from({ length: threshold - 1 }, (_, i) =>
      mockCommitResponse(i),
    );
    results.push(undefined as any, undefined as any);
    const handler = createHandleCommitmentResponses(results, false);
    expect(await handler()).toBeUndefined();
  });

  it('should return undefined if threshold met but buffer not elapsed and not all settled', async () => {
    const results = Array.from({ length: threshold }, (_, i) =>
      mockCommitResponse(i),
    );
    results.push(undefined as any);
    const handler = createHandleCommitmentResponses(results, false);

    expect(await handler()).toBeUndefined();

    await jest.advanceTimersByTimeAsync(bufferWaitTime / 2);
    expect(await handler()).toBeUndefined();
  });

  it('should return results if threshold met and buffer has elapsed', async () => {
    const results = Array.from({ length: threshold }, (_, i) =>
      mockCommitResponse(i),
    );
    results.push(undefined as any);
    const handler = createHandleCommitmentResponses(results, false);

    expect(await handler()).toBeUndefined();

    await jest.advanceTimersByTimeAsync(bufferWaitTime + 50);

    const finalResult = await handler();
    expect(finalResult).toBeDefined();
    expect(finalResult).toHaveLength(threshold);
  });

  it('should return results if threshold met and all have settled (before buffer)', async () => {
    const results = Array.from({ length: threshold + 1 }, (_, i) =>
      mockCommitResponse(i),
    );
    const handler = createHandleCommitmentResponses(results, true);

    const finalResult = await handler();
    expect(finalResult).toBeDefined();
    expect(finalResult).toHaveLength(threshold + 1);
  });

  it('should throw TOPRFError if threshold not met when all settled', async () => {
    const results = Array.from({ length: threshold - 1 }, (_, i) =>
      mockCommitResponse(i),
    );
    const handler = createHandleCommitmentResponses(results, true);

    await expect(handler()).rejects.toBeInstanceOf(TOPRFError);
    await expect(handler()).rejects.toThrow(
      `Threshold not met after all requests processed. Expected: ${threshold}, got: ${threshold - 1}`,
    );
  });

  it('should handle results array changing between calls', async () => {
    const initialResults = Array.from({ length: threshold - 1 }, (_, i) =>
      mockCommitResponse(i),
    );
    const handler1 = createHandleCommitmentResponses(initialResults, false);
    expect(await handler1()).toBeUndefined();

    const finalResultsResults = Array.from({ length: threshold }, (_, i) =>
      mockCommitResponse(i),
    );
    const handler2 = createHandleCommitmentResponses(finalResultsResults, true);

    const finalResult = await handler2();
    expect(finalResult).toBeDefined();
    expect(finalResult).toHaveLength(threshold);
  });

  it('should track thresholdMetTime correctly across calls', async () => {
    const resultsMeetThreshold = Array.from({ length: threshold }, (_, i) =>
      mockCommitResponse(i),
    );
    resultsMeetThreshold.push(undefined as any);
    const handler = createHandleCommitmentResponses(
      resultsMeetThreshold,
      false,
    );

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
    expect(finalResult).toHaveLength(threshold);
  });
});
