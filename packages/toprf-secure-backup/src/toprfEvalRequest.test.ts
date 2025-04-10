import { toBytes } from '@noble/hashes/utils';

import { EXISTING_USER_AUTHENTICATION_THRESHOLD } from './constants';
import type { NodeAuthTokens } from './interfaces';
import type { ToprfEvalJRPCResponse } from './jrpcInterfaces';
import { recoverTOPRFSeed, validateSeed } from './toprfEvalRequest';

describe('toprfEvalRequest', () => {
  describe('validateSeed', () => {
    it('should throw error if insufficient valid responses', async () => {
      // Create fewer responses than the threshold
      const insufficientResponses: ToprfEvalJRPCResponse[] = Array(
        EXISTING_USER_AUTHENTICATION_THRESHOLD - 1,
      )
        .fill(0)
        .map(() => ({
          jsonrpc: '2.0',
          id: 1,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: 1,
            shareKeyIndex: 1,
            pubKey: 'pubKey',
          },
        }));

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, insufficientResponses),
      ).rejects.toThrow(
        `Insufficient toprf eval request results, expected ${EXISTING_USER_AUTHENTICATION_THRESHOLD} but got ${EXISTING_USER_AUTHENTICATION_THRESHOLD - 1}`,
      );
    });

    it('should throw error if threshold auth pub key cannot be derived', async () => {
      // Create responses with different pubKeys so threshold cannot be derived
      const inconsistentResponses: ToprfEvalJRPCResponse[] = Array(
        EXISTING_USER_AUTHENTICATION_THRESHOLD,
      )
        .fill(0)
        .map((_, i) => ({
          jsonrpc: '2.0',
          id: 1,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: i + 1,
            shareKeyIndex: 1,
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
        EXISTING_USER_AUTHENTICATION_THRESHOLD - 1,
      )
        .fill(0)
        .map((_, i) => ({
          jsonrpc: '2.0',
          id: 1,
          result: {
            blindedOutputX: 'abc',
            blindedOutputY: 'def',
            nodeIndex: i + 1,
            shareKeyIndex: 1,
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
          shareKeyIndex: 1,
          pubKey: 'pubKey',
        },
      };

      const responsesWithIncomplete = [...validResponses, incompleteResponse];

      const userInput = toBytes('test-password');
      const randomScalar = 1n;

      await expect(
        validateSeed(userInput, randomScalar, responsesWithIncomplete),
      ).rejects.toThrow(
        `Insufficient valid blinded outputs, expected: ${EXISTING_USER_AUTHENTICATION_THRESHOLD}, received: ${EXISTING_USER_AUTHENTICATION_THRESHOLD - 1}`,
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
          verifier: 'test-verifier',
          verifierId: 'test-verifier-id',
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
          verifier: 'test-verifier',
          verifierId: 'test-verifier-id',
          userInput: toBytes('test-password'),
        }),
      ).rejects.toThrow('Endpoint not found for node index 4');
    });
  });
});
