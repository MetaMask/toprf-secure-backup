import { secp256k1 } from '@noble/curves/secp256k1';
import { toBytes } from '@noble/hashes/utils';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { TOPRF_EVAL_THRESHOLD } from './constants';
import { TOPRFErrorCode } from './errors';
import type { NodeAuthTokens } from './interfaces';
import type { ToprfEvalJRPCResponse } from './jrpcInterfaces';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF, generateRandomScalar } from './oprf';
import { storeKeyShares } from './storeSharesRequest';
import { recoverTOPRFSeed, validateSeed } from './toprfEvalRequest';
import { createNodeEndpointsMap } from './utils';
import { generateIdToken, generateRandomUserId } from '../tests/testHelpers';

describe('toprfEvalRequest', () => {
  describe('validateSeed', () => {
    it('should throw error if insufficient valid responses', async () => {
      // Create fewer responses than the threshold
      const insufficientResponses: ToprfEvalJRPCResponse[] = Array(
        TOPRF_EVAL_THRESHOLD - 1,
      )
        .fill(0)
        .map(() => ({
          jsonrpc: '2.0',
          id: 1,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: 1,
            keyShareIndex: 1,
            pubKey: 'pubKey',
          },
        }));

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, insufficientResponses),
      ).rejects.toThrow(
        `Insufficient toprf eval request results, expected ${TOPRF_EVAL_THRESHOLD} but got ${TOPRF_EVAL_THRESHOLD - 1}`,
      );
    });

    it('should throw error if threshold auth pub key cannot be derived', async () => {
      // Create responses with different pubKeys so threshold cannot be derived
      const inconsistentResponses: ToprfEvalJRPCResponse[] = Array(
        TOPRF_EVAL_THRESHOLD,
      )
        .fill(0)
        .map((_, i) => ({
          jsonrpc: '2.0',
          id: 1,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: i + 1,
            keyShareIndex: 1,
            pubKey: `pubKey${i}`,
          },
        }));

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, inconsistentResponses),
      ).rejects.toThrow('Could not derive threshold auth pub key');
    });

    it('should throw error when responses contain missing blinded outputs leading to insufficient valid responses', async () => {
      const validResponses: ToprfEvalJRPCResponse[] = Array(
        TOPRF_EVAL_THRESHOLD - 1,
      )
        .fill(0)
        .map((_, i) => ({
          jsonrpc: '2.0',
          id: 1,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: i + 1,
            keyShareIndex: 1,
            pubKey: 'pubKey',
          },
        }));

      const incompleteResponse: ToprfEvalJRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          // Add a response with missing values
          blindedOutputX: undefined as unknown as string,
          blindedOutputY: 'def',
          nodeIndex: 5,
          keyShareIndex: 1,
          pubKey: 'pubKey',
        },
      };

      const responsesWithIncomplete = [...validResponses, incompleteResponse];

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, responsesWithIncomplete),
      ).rejects.toThrow(
        `Insufficient valid blinded outputs, expected: ${TOPRF_EVAL_THRESHOLD}, received: ${TOPRF_EVAL_THRESHOLD - 1}`,
      );
    });
  });

  describe('recoverTOPRFSeed', () => {
    it('should throw error if fewer than 3 auth tokens are provided', async () => {
      const insufficientAuthTokens: NodeAuthTokens = [
        { authToken: 'token1', nodeIndex: 1, nodePubKey: 'pubKey1' },
        { authToken: 'token2', nodeIndex: 2, nodePubKey: 'pubKey2' },
      ];

      await expect(
        recoverTOPRFSeed({
          authTokens: insufficientAuthTokens,
          nodeEndpointsMap: { 1: 'endpoint1', 2: 'endpoint2' },
          authConnectionId: 'test-auth-connection-id',
          userId: 'test-user-id',
          userInput: toBytes('test-password'),
        }),
      ).rejects.toThrow('At least 3 auth tokens are required');
    });

    it('should throw error if endpoint not found for node index', async () => {
      // Create auth tokens where one of them has a nodeIndex not in the nodeEndpointsMap
      const authTokens: NodeAuthTokens = [
        { authToken: 'token1', nodeIndex: 1, nodePubKey: 'pubKey1' },
        { authToken: 'token2', nodeIndex: 2, nodePubKey: 'pubKey2' },
        { authToken: 'token3', nodeIndex: 3, nodePubKey: 'pubKey3' },
        { authToken: 'token4', nodeIndex: 4, nodePubKey: 'pubKey4' }, // No endpoint for this index
      ];

      const nodeEndpointsMap = {
        1: 'endpoint1',
        2: 'endpoint2',
        3: 'endpoint3',
      };

      await expect(
        recoverTOPRFSeed({
          authTokens,
          nodeEndpointsMap,
          authConnectionId: 'test-auth-connection-id',
          userId: 'test-user-id',
          userInput: toBytes('test-password'),
        }),
      ).rejects.toThrow('Endpoint not found for node index 4');
    });

    it('should trigger rate limiting after multiple password attempts', async function () {
      // Set up test environment
      const privKey = secp256k1.utils.randomPrivateKey();
      const pubKey = secp256k1.ProjectivePoint.fromPrivateKey(privKey);

      const nodeDetailManager = new NodeDetailManager({
        network: 'sapphire_devnet',
      });

      const authConnectionId = 'torus-test-health';
      const userId = generateRandomUserId();
      const { torusNodeSSSEndpoints, torusIndexes } =
        await nodeDetailManager.getNodeDetails({
          verifier: authConnectionId,
          verifierId: userId,
        });

      if (!torusNodeSSSEndpoints || !torusIndexes) {
        throw new Error('Failed to get node details');
      }

      // Create endpoints map and prepare tokens
      const nodeEndpointsMap = createNodeEndpointsMap(
        torusNodeSSSEndpoints,
        torusIndexes,
      );

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

      // Prepare password, key and shares
      const passwordBytes = toBytes('correct-password');
      const oprfKey = generateRandomScalar();
      const seed = await OPRF.localEval(oprfKey, passwordBytes);
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

      // Make 3 calls - all should succeed without rate limiting
      for (let i = 0; i < 3; i++) {
        const attemptResult = await recoverTOPRFSeed({
          authTokens: authTokensData,
          nodeEndpointsMap: selectedEndpointsMap,
          authConnectionId,
          userId,
          userInput: passwordBytes,
        });

        expect(attemptResult.seed).toBeDefined();
        expect(attemptResult.keyShareIndex).toBe(1);

        const recoveredAuthKeyPair = deriveAuthenticationKeyPair(
          attemptResult.seed,
        );
        expect(recoveredAuthKeyPair.pk).toStrictEqual(authKeyPair.pk);
        expect(recoveredAuthKeyPair.sk).toStrictEqual(authKeyPair.sk);
      }

      // 4th call should trigger rate limiting
      await expect(async () => {
        return recoverTOPRFSeed({
          authTokens: authTokensData,
          nodeEndpointsMap: selectedEndpointsMap,
          authConnectionId,
          userId,
          userInput: passwordBytes,
        });
      }).rejects.toMatchObject({
        code: TOPRFErrorCode.RateLimitExceeded,
        message: expect.stringContaining('Rate limit error from server'),
        meta: {
          rateLimitDetails: {
            message: expect.any(String),
            remainingTime: expect.any(Number),
          },
        },
      });
    });
  });
});
