import { toBytes } from '@noble/hashes/utils';

import { TOPRF_EVAL_THRESHOLD, JsonRpcErrorCodes } from './constants';
import { TOPRFErrorCode } from './errors';
import type { NodeAuthTokens } from './interfaces';
import type { ToprfEvalJRPCResponse } from './jrpcInterfaces';
import { recoverTOPRFSeed, validateSeed } from './toprfEvalRequest';

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
            guessCount: 1,
            lockTimeSeconds: 0,
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
            guessCount: 1,
            lockTimeSeconds: 0,
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
            guessCount: 1,
            lockTimeSeconds: 0,
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
          guessCount: 1,
          lockTimeSeconds: 0,
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

    it('should throw auth token expired error when found in responses', async () => {
      const responsesWithExpiredToken: ToprfEvalJRPCResponse[] = [
        {
          jsonrpc: '2.0',
          id: 1,
          error: {
            code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
            message: 'Auth token expired',
          },
        },
        {
          jsonrpc: '2.0',
          id: 2,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: 1,
            keyShareIndex: 1,
            pubKey: 'pubKey',
            guessCount: 1,
            lockTimeSeconds: 0,
          },
        },
        {
          jsonrpc: '2.0',
          id: 3,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: 2,
            keyShareIndex: 1,
            pubKey: 'pubKey',
            guessCount: 1,
            lockTimeSeconds: 0,
          },
        },
      ];

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, responsesWithExpiredToken),
      ).rejects.toMatchObject({
        code: TOPRFErrorCode.AuthTokenExpired,
        message: expect.stringContaining('Auth token expired'),
      });
    });

    it('should throw auth token expired error before rate limit error when both are present', async () => {
      const responsesWithBothErrors: ToprfEvalJRPCResponse[] = [
        {
          jsonrpc: '2.0',
          id: 1,
          error: {
            code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
            message: 'Auth token expired',
          },
        },
        {
          jsonrpc: '2.0',
          id: 2,
          error: {
            code: -32602,
            message: 'Rate limit exceeded',
            data: {
              message: 'Too many requests',
              remaining_time: 300,
              lock_time: 60,
              guess_count: 5,
            },
          },
        },
        {
          jsonrpc: '2.0',
          id: 3,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: 1,
            keyShareIndex: 1,
            pubKey: 'pubKey',
            guessCount: 1,
            lockTimeSeconds: 0,
          },
        },
      ];

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, responsesWithBothErrors),
      ).rejects.toMatchObject({
        code: TOPRFErrorCode.AuthTokenExpired,
        message: expect.stringContaining('Auth token expired'),
      });
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
  });
});
