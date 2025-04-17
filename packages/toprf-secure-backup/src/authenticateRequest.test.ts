import { keccak256AndHexify } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import {
  authenticateUser,
  validateAndWaitForAllAuthResponses,
  validateThresholdAuthenticateResponses,
} from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { TOPRFError } from './errors';
import type { AuthJRPCResponse, AuthRequestResult } from './jrpcInterfaces';
import { createNodeEndpointsMap } from './utils';
import {
  generateIdToken,
  generateRandomVerifierId,
} from '../tests/testHelpers';

describe('validateThresholdAuthenticateResponses', () => {
  /**
   *
   * @param nodeIndex - The node index to be used for the mock response.
   * @returns The mock response.
   */
  const mockAuthResult = (nodeIndex: number): AuthRequestResult => ({
    pubKey: '04abcd1234',
    keyIndex: 1,
    nodeIndex,
    authToken: 'authToken',
    nodePubKey: 'nodePubKey',
  });

  /**
   *
   * @param result - The result to be used for the mock response.
   * @param error - The error to be used for the mock response.
   * @returns The mock response.
   */
  const createMockResponse = (
    result?: AuthRequestResult,
    error?: any,
  ): AuthJRPCResponse => ({
    jsonrpc: '2.0',
    id: 1,
    result: result as AuthRequestResult,
    error,
  });

  it('should validate successful responses for existing user', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1) }),
      createMockResponse({ ...mockAuthResult(2) }),
      createMockResponse({ ...mockAuthResult(3) }),
      createMockResponse({ ...mockAuthResult(4) }),
    ];

    const result = await validateThresholdAuthenticateResponses(responses);
    expect(result.authRequestResults).toStrictEqual(
      responses.map((res) => res.result),
    );
  });

  it('should validate successful responses for new user', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1) }),
      createMockResponse({ ...mockAuthResult(2) }),
      createMockResponse({ ...mockAuthResult(3) }),
      createMockResponse({ ...mockAuthResult(4) }),
      createMockResponse({ ...mockAuthResult(5) }),
    ];

    const result = await validateThresholdAuthenticateResponses(responses);
    expect(result.authRequestResults).toStrictEqual(
      responses.map((res) => res.result),
    );
  });

  it('should reject if insufficient responses', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1) }),
      createMockResponse({ ...mockAuthResult(2) }),
    ];

    await expect(
      validateThresholdAuthenticateResponses(responses),
    ).rejects.toBeInstanceOf(TOPRFError);
  });

  it('should reject if responses contain errors', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1) }),
      createMockResponse({ ...mockAuthResult(2) }),
      createMockResponse(
        { ...mockAuthResult(3) },
        { code: 500, message: 'Server error' },
      ),
      createMockResponse(
        { ...mockAuthResult(4) },
        { code: 500, message: 'Server error' },
      ),
      createMockResponse(
        { ...mockAuthResult(5) },
        { code: 500, message: 'Server error' },
      ),
    ];

    await expect(
      validateThresholdAuthenticateResponses(responses),
    ).rejects.toBeInstanceOf(TOPRFError);
  });

  it('should reject if pubKeys do not match for existing user', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1), pubKey: '04abcd1234' }),
      createMockResponse({ ...mockAuthResult(2), pubKey: '04abcd1231' }),
      createMockResponse({ ...mockAuthResult(3), pubKey: '04abcd1232' }),
      createMockResponse({ ...mockAuthResult(4), pubKey: '04abcd1238' }),
      createMockResponse({ ...mockAuthResult(5), pubKey: '04abcd1231' }),
    ];

    await expect(
      validateThresholdAuthenticateResponses(responses),
    ).rejects.toBeInstanceOf(TOPRFError);
  });

  it('should reject if keyIndexes do not match', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1), keyIndex: 1 }),
      createMockResponse({ ...mockAuthResult(2), keyIndex: 1 }),
      createMockResponse({ ...mockAuthResult(3), keyIndex: 3 }),
      createMockResponse({ ...mockAuthResult(4), keyIndex: 4 }),
      createMockResponse({ ...mockAuthResult(5), keyIndex: 5 }),
    ];

    await expect(
      validateThresholdAuthenticateResponses(responses),
    ).rejects.toBeInstanceOf(TOPRFError);
  });

  it('should validate mixed responses for new user', async () => {
    const responses: AuthJRPCResponse[] = [
      createMockResponse({ ...mockAuthResult(1), nodeIndex: 1 }),
      createMockResponse(undefined, { code: 500, message: 'Server error' }),
      createMockResponse({ ...mockAuthResult(2), nodeIndex: 3 }),
      createMockResponse({ ...mockAuthResult(3), nodeIndex: 4 }),
      createMockResponse({ ...mockAuthResult(4), nodeIndex: 5 }),
    ];

    const result = await validateThresholdAuthenticateResponses(responses);
    expect(result.authRequestResults).toStrictEqual(
      responses.filter((res) => res.result).map((res) => res.result),
    );
  });
});

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

  it('should to send a authenticate request for a single id verifier', async function () {
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
    expect(isNewUser).toBe(false);
  });
});

describe('validateAndWaitForAuthResponses', () => {
  /**
   *
   * @param nodeIndex - The node index to be used for the mock response.
   * @param isNewUser - Whether the user is new or not.
   * @returns The mock response.
   */
  const mockAuthResponse = (
    nodeIndex: number,
    isNewUser = false,
  ): AuthJRPCResponse => ({
    jsonrpc: '2.0',
    id: 1,
    result: {
      nodeIndex,
      authToken: 'token',
      nodePubKey: 'pubKey',
      pubKey: isNewUser ? '' : 'pubKey',
      keyIndex: 1,
    },
  });

  /**
   *
   * @param count - The number of promises to create.
   * @returns The mock promises.
   */
  const createMockAuthPromises = (count: number): Promise<AuthJRPCResponse>[] =>
    Array.from({ length: count }, async (_, i) =>
      Promise.resolve(mockAuthResponse(i)),
    );

  it('should return results immediately when all promises are complete', async () => {
    const responses = [
      mockAuthResponse(1),
      mockAuthResponse(2),
      mockAuthResponse(3),
      mockAuthResponse(4),
      mockAuthResponse(5),
    ];
    const promiseArr = createMockAuthPromises(5);
    const startTime = Date.now();
    const bufferWaitTime = 500;

    const result = await validateAndWaitForAllAuthResponses(
      responses,
      promiseArr,
      startTime,
      bufferWaitTime,
    );

    expect(result.authRequestResults).toHaveLength(5);
    expect(result.isNewUser).toBe(false);
  });

  it('should return results when buffer time has elapsed', async () => {
    const responses = [
      mockAuthResponse(1),
      mockAuthResponse(2),
      mockAuthResponse(3),
      mockAuthResponse(4),
    ];
    const promiseArr = createMockAuthPromises(5);
    const startTime = Date.now() - 600;
    const bufferWaitTime = 500;

    const result = await validateAndWaitForAllAuthResponses(
      responses,
      promiseArr,
      startTime,
      bufferWaitTime,
    );

    expect(result.authRequestResults).toHaveLength(responses.length);
  });

  it('should throw error to continue waiting if buffer time not elapsed', async () => {
    const responses = [
      mockAuthResponse(1),
      mockAuthResponse(2),
      mockAuthResponse(3),
      mockAuthResponse(4),
    ];
    const promiseArr = createMockAuthPromises(5);
    const startTime = Date.now();
    const bufferWaitTime = 500;

    await expect(
      validateAndWaitForAllAuthResponses(
        responses,
        promiseArr,
        startTime,
        bufferWaitTime,
      ),
    ).rejects.toThrow(
      'Predicate Error: Threshold achieved, Waiting for maximum number of requests to complete',
    );
  });
});
