import { TOPRFError } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import {
  authenticateUser,
  validateThresholdAuthenticateResponses,
} from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import type { AuthJRPCResponse, AuthRequestResult } from './jrpcInterfaces';
import { generateIdToken } from '../tests/testHelpers';

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
    ];

    const result = await validateThresholdAuthenticateResponses(responses);
    expect(result).toStrictEqual(responses.map((res) => res.result));
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
    expect(result).toStrictEqual(responses.map((res) => res.result));
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
    ];

    const result = await validateThresholdAuthenticateResponses(responses);
    expect(result).toStrictEqual(
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

  it('should create a authenticate request', async function () {
    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id';
    const idToken = generateIdToken(verifierID, 'ES256');
    const sessionPubKeyX = pubKey.x.toString(16);
    const sessionPubKeyY = pubKey.y.toString(16);
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
    const authResult = await authenticateUser({
      idToken,
      verifier,
      verifierID,
      sessionPrivateKey: privKey,
      endpoints: torusNodeSSSEndpoints,
      commitmentSignatures: commitmentResults,
    });
    expect(authResult).toBeDefined();
    expect(authResult.length).toBeGreaterThanOrEqual(3);
  });
});
