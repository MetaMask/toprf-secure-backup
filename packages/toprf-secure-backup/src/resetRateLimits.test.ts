import type { JsonRpcVersion } from '@metamask/auth-network-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { toBytes } from '@noble/hashes/utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { TOPRFError } from './errors';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { generateRandomScalar, OPRF } from './oprf';
import {
  resetRateLimits,
  validateThresholdResetRateLimitResponses,
} from './resetRateLimits';
import { storeKeyShares } from './storeSharesRequest';
import { createNodeEndpointsMap } from './utils';
import {
  generateIdToken,
  generateRandomVerifierId,
} from '../tests/testHelpers';

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
    const verifierId = generateRandomVerifierId();

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

    const passwordBytes = toBytes('test-input');
    const oprfKey = generateRandomScalar();
    const seed = OPRF.localEval(oprfKey, passwordBytes);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId,
      authTokens: authTokensData,
      shareKeyIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();

    const result = await resetRateLimits({
      authTokens: authTokensData,
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId,
      authPrivKey: authKeyPair.sk,
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
    const verifierId = generateRandomVerifierId();

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

    const passwordBytes = toBytes('test-input');
    const oprfKey = generateRandomScalar();
    const seed = OPRF.localEval(oprfKey, passwordBytes);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    const storeSharesResponse = await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId,
      authTokens: authTokensData,
      shareKeyIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });

    expect(storeSharesResponse).toBeDefined();
    expect(storeSharesResponse.error).toBeUndefined();

    await expect(
      resetRateLimits({
        authTokens: authTokensData,
        nodeEndpointsMap: {
          ...selectedEndpointsMap,
          [authTokensData[0].nodeIndex]: '',
        },
        verifier,
        verifierId,
        authPrivKey: authKeyPair.sk,
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
