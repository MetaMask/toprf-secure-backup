import {
  filterCompletedRequests,
  safeStringify,
  Some,
  toSnakeCaseKeys,
} from '@metamask/auth-network-utils';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import { TOPRFError } from './errors';
import type { NodeAuthTokens } from './interfaces';
import type {
  ResetRateLimitJRPCRequest,
  ResetRateLimitJRPCRequestParams,
  ResetRateLimitJRPCResponse,
} from './jrpcInterfaces';
import {
  checkAuthTokenErrors,
  createEthereumSignature,
  mergeEndpointsWithAuthTokens,
  postJRPCRequest,
  preserveKeyOrder,
} from './utils';

/**
 * Creates the parameters for the reset rate limit request
 *
 * @param authToken - The auth token issued by node to authenticate the request.
 * @param signature - The signature of the signedData using user's authentication key.
 * @param signedData - The data that is signed for to validate if user has access to authentication key.
 * @param authConnectionId - The auth connection name.
 * @param userId - The user id of the user issued by authentication service.
 * @param groupedAuthConnectionId - The grouped auth connection name used for authentication with aggregate (single id) verifier.
 * @returns The parameters for the reset rate limit jrpc request.
 */
const createResetRateLimitRequestParams = (
  authToken: string,
  signature: string,
  signedData: string,
  authConnectionId: string,
  userId: string,
  groupedAuthConnectionId?: string,
): ResetRateLimitJRPCRequestParams => {
  return {
    authToken,
    signature,
    signedData,
    verifier: groupedAuthConnectionId ?? authConnectionId,
    verifierId: userId,
  };
};

/**
 * Sends a reset rate limit request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the reset rate limit request
 * @param params - The parameters for the reset rate limit request
 * @param client - Optional client identifier sent as the `x-web3-client` header.
 * @returns promise of reset rate limit response.
 */
export const sendResetRateLimitRequest = async (
  endpoint: string,
  params: ResetRateLimitJRPCRequestParams,
  client?: string,
): Promise<ResetRateLimitJRPCResponse> => {
  const resetRateLimitJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.RESET_RATE_LIMIT_REQUEST,
    params,
  ) as ResetRateLimitJRPCRequest;

  return postJRPCRequest<ResetRateLimitJRPCResponse>(
    endpoint,
    resetRateLimitJRPCRequest,
    client,
  );
};

/**
 * Validates the reset rate limit responses
 *
 * @param resultArr - The reset rate limit request result
 * @param threshold - The threshold for the number reset rate limit responses to be valid
 *
 * @returns true if the number of valid reset rate limit responses is greater than or equal to the threshold.
 * @throws {TOPRFError.insufficientValidResponses} - If the number of valid reset rate limit responses is less than the threshold.
 */
export const validateThresholdResetRateLimitResponses = (
  resultArr: ResetRateLimitJRPCResponse[],
  threshold: number,
): boolean => {
  // Check for auth token errors before filtering responses
  const authTokenError = checkAuthTokenErrors(resultArr);
  if (authTokenError) {
    throw authTokenError;
  }

  const completedRequests =
    filterCompletedRequests<ResetRateLimitJRPCResponse>(resultArr);
  if (completedRequests.length < threshold) {
    throw TOPRFError.insufficientValidResponses(
      `invalid reset rate limit results, expected ${threshold} but got ${completedRequests.length}`,
    );
  }
  return true;
};

/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.authConnectionId - The auth connection name used for authentication.
 * @param params.groupedAuthConnectionId - The grouped auth connection name used for authentication with aggregate (single id) verifier.
 * @param params.userId - The user id of the user issued by authentication service.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 * @param params.authPrivKey - The user's authentication private key as bigint for signing the request.
 * @param params.client - Optional client identifier sent as the `x-web3-client` header.
 *
 * @returns - A promise that resolves when the rate limit is reset successfully.
 */
export const resetRateLimits = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Record<number, string>;
  authConnectionId: string;
  groupedAuthConnectionId?: string;
  userId: string;
  authPrivKey: bigint;
  client?: string;
}): Promise<boolean> => {
  const {
    authTokens,
    nodeEndpointsMap,
    authConnectionId,
    groupedAuthConnectionId,
    userId,
    authPrivKey,
    client,
  } = params;

  const endpointsWithAuthTokens = mergeEndpointsWithAuthTokens(
    authTokens,
    nodeEndpointsMap,
  );

  const promises = endpointsWithAuthTokens.map(
    async ({ endpoint, authToken }) => {
      const dataToSign = toSnakeCaseKeys({
        timestamp: Date.now(),
        nodeIndex: authToken.nodeIndex,
        action: 'reset_ratelimit',
      });

      const jsonData = safeStringify(dataToSign, { cmp: preserveKeyOrder });
      const dataHash = keccak256(jsonData);
      const signature = createEthereumSignature(dataHash, authPrivKey);

      const requestParams = createResetRateLimitRequestParams(
        authToken.authToken,
        signature,
        jsonData,
        authConnectionId,
        userId,
        groupedAuthConnectionId,
      );
      return sendResetRateLimitRequest(endpoint, requestParams, client);
    },
  );

  return Some<ResetRateLimitJRPCResponse, boolean>(
    promises,
    async (resultArr) =>
      validateThresholdResetRateLimitResponses(resultArr, authTokens.length),
  );
};
