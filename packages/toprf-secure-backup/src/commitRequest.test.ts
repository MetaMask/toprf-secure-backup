import { TOPRFError } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import {
  commitIdToken,
  validateThresholdCommitmentResponses,
} from './commitRequest';
import type {
  CommitmentJRPCResponse,
  CommitmentRequestResult,
} from './jrpcInterfaces';
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

    const endpoints = [...torusNodeSSSEndpoints];
    endpoints[0] = 'https://invalid-endpoint';

    const commitmentResults = await commitIdToken({
      idToken,
      verifier,
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
    const endpoints = [...torusNodeSSSEndpoints];
    // node endpoints without path, so that test won't get stucked.
    endpoints[0] = endpoints[0].replace('/jrpc', '');
    endpoints[1] = endpoints[1].replace('/jrpc', '');
    endpoints[2] = endpoints[1].replace('/jrpc', '');
    endpoints[3] = endpoints[1].replace('/jrpc', '');
    endpoints[4] = endpoints[1].replace('/jrpc', '');

    await expect(
      commitIdToken({
        idToken,
        verifier,
        sessionPubKeyX,
        sessionPubKeyY,
        endpoints,
      }),
    ).rejects.toBeDefined();
  });
});

describe('validateThresholdCommitmentResponses', () => {
  /**
   * Creates a mock commitment result
   *
   * @param nodeIndex - The index of the node
   * @returns A mock commitment result
   */
  const mockCommitmentResult = (
    nodeIndex: number,
  ): CommitmentRequestResult => ({
    signature: 'mockSignature',
    nodeIndex,
    nodePubX: 'mockNodePubX',
    nodePubY: 'mockNodePubY',
    data: 'mockData',
  });

  /**
   * Creates a mock commitment response.
   *
   * @param result - The result of the commitment
   * @param error - The error of the commitment.
   * @param error.code - The code of the error.
   * @param error.message - The message of the error.
   * @returns A mock commitment response.
   */
  const createMockResponse = (
    result?: CommitmentRequestResult,
    error?: { code: number; message: string },
  ): CommitmentJRPCResponse => ({
    jsonrpc: '2.0',
    id: 1,
    result,
    error: error as { code: number; message: string; data?: unknown },
  });

  it('should validate successful responses', async () => {
    const responses: CommitmentJRPCResponse[] = [
      createMockResponse(mockCommitmentResult(1)),
      createMockResponse(mockCommitmentResult(2)),
      createMockResponse(mockCommitmentResult(3)),
      createMockResponse(mockCommitmentResult(4)),
    ];

    const result = await validateThresholdCommitmentResponses(responses);
    expect(result).toHaveLength(4);
    expect(result).toStrictEqual(responses.map((res) => res.result));
  });

  it('should filter out responses with errors', async () => {
    const responses: CommitmentJRPCResponse[] = [
      createMockResponse(mockCommitmentResult(1)),
      createMockResponse(undefined, { code: 500, message: 'Server error' }),
      createMockResponse(mockCommitmentResult(3)),
      createMockResponse(mockCommitmentResult(4)),
      createMockResponse(mockCommitmentResult(5)),
    ];

    const result = await validateThresholdCommitmentResponses(responses);
    expect(result).toHaveLength(4);
    expect(result).toStrictEqual([
      mockCommitmentResult(1),
      mockCommitmentResult(3),
      mockCommitmentResult(4),
      mockCommitmentResult(5),
    ]);
  });

  it('should filter out responses with missing results', async () => {
    const responses: CommitmentJRPCResponse[] = [
      createMockResponse(mockCommitmentResult(1)),
      createMockResponse(undefined),
      createMockResponse(mockCommitmentResult(3)),
      createMockResponse(mockCommitmentResult(4)),
      createMockResponse(mockCommitmentResult(5)),
    ];

    const result = await validateThresholdCommitmentResponses(responses);
    expect(result).toHaveLength(4);
    expect(result).toStrictEqual([
      mockCommitmentResult(1),
      mockCommitmentResult(3),
      mockCommitmentResult(4),
      mockCommitmentResult(5),
    ]);
  });

  it('should throw an error if empty response array', async () => {
    const responses: CommitmentJRPCResponse[] = [];
    await expect(
      validateThresholdCommitmentResponses(responses),
    ).rejects.toBeInstanceOf(TOPRFError);
  });

  it('should throw if all invalid responses', async () => {
    const responses: CommitmentJRPCResponse[] = [
      createMockResponse(undefined, { code: 500, message: 'Error 1' }),
      createMockResponse(undefined, { code: 500, message: 'Error 2' }),
      createMockResponse(undefined, { code: 500, message: 'Error 3' }),
    ];

    await expect(
      validateThresholdCommitmentResponses(responses),
    ).rejects.toBeInstanceOf(TOPRFError);
  });
});
