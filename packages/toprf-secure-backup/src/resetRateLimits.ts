import { Some, TOPRFError } from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type { NodeAuthTokens } from './interfaces';
import type {
  ResetRateLimitJRPCRequest,
  ResetRateLimitJRPCRequestParams,
  ResetRateLimitJRPCResponse,
} from './jrpcInterfaces';
import { postJRPCRequest } from './utils';

/**
 * Creates the parameters for the reset rate limit request
 *
 * @param authToken - The auth token issued by node to authenticate the request.
 * @param signature - The signature of the signedData using user's authentication key.
 * @param signedData - The data that is signed for to validate if user has access to authentication key.
 * @param verifier - The verifier name.
 * @param verifierId - The verifier id of the user.
 *
 * @returns The parameters for the reset rate limit jrpc request.
 */
const createResetRateLimitRequestParams = (
  authToken: string,
  signature: string,
  signedData: string,
  verifier: string,
  verifierId: string,
): ResetRateLimitJRPCRequestParams => {
  return {
    authToken,
    signature,
    signedData,
    verifier,
    verifierId,
  };
};

/**
 * Sends a reset rate limit request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the reset rate limit request
 * @param params - The parameters for the reset rate limit request
 * @returns promise of reset rate limit response.
 */
export const sendResetRateLimitRequest = async (
  endpoint: string,
  params: ResetRateLimitJRPCRequestParams,
): Promise<ResetRateLimitJRPCResponse> => {
  const resetRateLimitJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.RESET_RATE_LIMIT_REQUEST,
    params,
  ) as ResetRateLimitJRPCRequest;

  return postJRPCRequest<ResetRateLimitJRPCResponse>(
    endpoint,
    resetRateLimitJRPCRequest,
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
  const completedRequests = resultArr.filter(
    (res): res is ResetRateLimitJRPCResponse => {
      if (!res || typeof res !== 'object') {
        return false;
      }
      if ('error' in res && res.error) {
        return false;
      }
      if (!res.result) {
        return false;
      }
      return true;
    },
  );
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
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 *
 * @returns - A promise that resolves when the rate limit is reset successfully.
 */
export const resetRateLimits = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Map<number, string>;
  verifier: string;
  verifierId: string;
}): Promise<boolean> => {
  const { authTokens, nodeEndpointsMap, verifier, verifierId } = params;

  // TODO: get signature and signedData from the user authentication key.
  const signature = '0x';
  const signedData = JSON.stringify({
    node_index: 0,
    timestamp: Date.now().toString(),
    action: 'reset_ratelimit',
  });

  const promises: Promise<ResetRateLimitJRPCResponse>[] = [];
  for (const authToken of authTokens) {
    const endpoint = nodeEndpointsMap.get(authToken.nodeIndex);
    if (!endpoint) {
      throw TOPRFError.endpointNotFound(
        `Endpoint not found for node index ${authToken.nodeIndex}`,
      );
    }
    const requestParams = createResetRateLimitRequestParams(
      authToken.authToken,
      signature,
      signedData,
      verifier,
      verifierId,
    );
    promises.push(sendResetRateLimitRequest(endpoint, requestParams));
  }

  return Some<ResetRateLimitJRPCResponse, boolean>(
    promises,
    async (resultArr: ResetRateLimitJRPCResponse[]) =>
      validateThresholdResetRateLimitResponses(resultArr, authTokens.length),
  );
};
