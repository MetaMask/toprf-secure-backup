import { TOPRFError, type JsonRpcVersion } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import {
  resetRateLimits,
  validateThresholdResetRateLimitResponses,
} from './resetRateLimits';
import { createNodeEndpointsMap } from './utils';
import { generateIdToken } from '../tests/testHelpers';

// TODO: add more tests to test rate limit affect on multiple password input attempts in future.
describe('resetRateLimits', () => {
  let nodeDetailManager: NodeDetailManager;
  beforeAll(async function () {
    nodeDetailManager = new NodeDetailManager({
      network: 'sapphire_devnet',
    });
  });

  it('should reset rate limits without throwing', async function () {
    const verifier = 'torus-test-health';
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier,
        verifierId: 'dummy-id',
      });

    if (!torusNodeSSSEndpoints || !torusIndexes) {
      throw new Error('Failed to get node details');
    }

    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);
    const verifierId = `test-verifier-id-${Math.random()}`;

    const idToken = generateIdToken(verifierId, 'ES256');
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

    const result = await resetRateLimits({
      authTokens: authTokensData,
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId,
    });
    expect(result).toBe(true);
  });

  it('should fail if endpoint is not found for auth token node index', async function () {
    const verifier = 'torus-test-health';
    const { torusNodeSSSEndpoints, torusIndexes } =
      await nodeDetailManager.getNodeDetails({
        verifier,
        verifierId: 'dummy-id',
      });

    if (!torusNodeSSSEndpoints || !torusIndexes) {
      throw new Error('Failed to get node details');
    }

    const privKey = secp256k1.utils.randomPrivateKey();
    const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);
    const verifierId = `test-verifier-id-${Math.random()}`;

    const idToken = generateIdToken(verifierId, 'ES256');
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

    await expect(
      resetRateLimits({
        authTokens: authTokensData,
        nodeEndpointsMap: {
          ...selectedEndpointsMap,
          [authTokensData[0].nodeIndex]: '',
        },
        verifier,
        verifierId,
      }),
    ).rejects.toThrow(
      TOPRFError.endpointNotFound(
        `Endpoint not found for node index ${authTokensData[0].nodeIndex}`,
      ),
    );
  });
});

// add tests for validateThresholdResetRateLimitResponses
describe('validateThresholdResetRateLimitResponses', () => {
  it('should return true if the number of valid reset rate limit responses is greater than or equal to the threshold', () => {
    const resultArr = [
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: false,
      },
    ];

    const threshold = 3;
    expect(validateThresholdResetRateLimitResponses(resultArr, threshold)).toBe(
      true,
    );
  });

  it('should fail if the number of valid reset rate limit responses is less than the threshold', () => {
    const resultArr = [
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: false,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: false,
      },
    ];

    const threshold = 3;
    expect(() =>
      validateThresholdResetRateLimitResponses(resultArr, threshold),
    ).toThrow(
      TOPRFError.insufficientValidResponses(
        `invalid reset rate limit results, expected ${threshold} but got 2`,
      ),
    );
  });

  it('should fail if there are responses with errors and the number of valid responses is less than the threshold', () => {
    const resultArr = [
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        result: true,
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        error: {
          code: 1,
          message: 'error',
        },
      },
      {
        jsonrpc: '2.0' as JsonRpcVersion,
        id: 2,
        error: {
          code: 1,
          message: 'error',
        },
      },
    ];

    const threshold = 3;
    expect(() =>
      validateThresholdResetRateLimitResponses(resultArr, threshold),
    ).toThrow(
      TOPRFError.insufficientValidResponses(
        `invalid reset rate limit results, expected ${threshold} but got 2`,
      ),
    );
  });
});
