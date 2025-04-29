import {
  filterCompletedRequests,
  Some,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { hexToBytes } from '@noble/hashes/utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { GET_PUB_KEY_THRESHOLD, JRPC_METHODS } from './constants';
import { TOPRFError } from './errors';
import type { NodeAuthTokens } from './interfaces';
import type {
  GetPubKeyJRPCRequest,
  GetPubKeyJRPCRequestParams,
  GetPubKeyJRPCResponse,
} from './jrpcInterfaces';
import { mergeEndpointsWithAuthTokens, postJRPCRequest } from './utils';

/**
 * Creates the parameters for the get pub key request
 *
 * @param authToken - The auth issued by node to authenticate the request.
 * @param authConnectionId - The verifier name.
 * @param userId - The verifier id of the user.
 *
 * @returns The parameters for the get pub key jrpc request.
 */
const createGetPubKeyRequestParams = (
  authToken: string,
  authConnectionId: string,
  userId: string,
): GetPubKeyJRPCRequestParams => {
  return {
    authToken,
    verifier: authConnectionId,
    verifierId: userId,
  };
};

/**
 * Sends a get pub key request to the given endpoint.
 *
 * @param endpoint - The endpoint that the request will be sent to.
 * @param params - The request parameters.
 * @returns The pub key.
 */
const sendGetPubKeyRequest = async (
  endpoint: string,
  params: GetPubKeyJRPCRequestParams,
): Promise<GetPubKeyJRPCResponse> => {
  const getPubKeyJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.GET_PUB_KEY_REQUEST,
    params,
  ) as GetPubKeyJRPCRequest;

  return postJRPCRequest<GetPubKeyJRPCResponse>(endpoint, getPubKeyJRPCRequest);
};

/**
 * Validates the pub key responses.
 *
 * @param resultArr - The get pub key request result
 * @returns The get pub key request result
 */
export const validatePubKey = async (
  resultArr: GetPubKeyJRPCResponse[],
): Promise<Uint8Array> => {
  const completedRequests =
    filterCompletedRequests<GetPubKeyJRPCResponse>(resultArr);

  if (completedRequests.length < GET_PUB_KEY_THRESHOLD) {
    throw TOPRFError.insufficientValidResponses(
      `Insufficient get pub key request results, expected ${GET_PUB_KEY_THRESHOLD} but got ${completedRequests.length}`,
    );
  }
  const thresholdPubKey = thresholdSame(
    completedRequests.map((res) => res.result?.pubKey),
    GET_PUB_KEY_THRESHOLD,
  );

  if (!thresholdPubKey) {
    throw TOPRFError.couldNotDeriveThresholdAuthPubKey();
  }

  return hexToBytes(thresholdPubKey);
};

/**
 * Fetches the pub key from the nodes.
 *
 * @param params - The parameters for the get pub key request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.authConnectionId - The verifier name used for authentication.
 * @param params.userId - The verifier id of the user.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the toprf eval request.
 *
 * @returns - A promise that resolves with the key pair seed successfully.
 */
export const getPubKey = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Record<number, string>;
  authConnectionId: string;
  userId: string;
}): Promise<Uint8Array> => {
  const { authTokens, nodeEndpointsMap, authConnectionId, userId } = params;

  if (authTokens.length < GET_PUB_KEY_THRESHOLD) {
    throw TOPRFError.insufficientAuthTokens(
      `At least ${GET_PUB_KEY_THRESHOLD} auth tokens are required.`,
    );
  }

  const endpointsWithAuthTokens = mergeEndpointsWithAuthTokens(
    authTokens,
    nodeEndpointsMap,
  );

  const promises = endpointsWithAuthTokens.map(
    async ({ endpoint, authToken }) => {
      const requestParams = createGetPubKeyRequestParams(
        authToken.authToken,
        authConnectionId,
        userId,
      );
      return sendGetPubKeyRequest(endpoint, requestParams);
    },
  );

  return Some<GetPubKeyJRPCResponse, Uint8Array>(promises, async (resultArr) =>
    validatePubKey(resultArr),
  );
};
