import {
  filterCompletedRequests,
  Some,
  thresholdSame,
  TOPRFError,
} from '@metamask/auth-network-utils';
import { hexToBytes } from '@noble/hashes/utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import {
  EXISTING_USER_AUTHENTICATION_THRESHOLD,
  JRPC_METHODS,
} from './constants';
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
 * @param verifier - The verifier name.
 * @param verifierId - The verifier id of the user.
 *
 * @returns The parameters for the get pub key jrpc request.
 */
const createGetPubKeyRequestParams = (
  authToken: string,
  verifier: string,
  verifierId: string,
): GetPubKeyJRPCRequestParams => {
  return {
    authToken,
    verifier,
    verifierId,
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

  if (completedRequests.length < EXISTING_USER_AUTHENTICATION_THRESHOLD) {
    throw TOPRFError.insufficientValidResponses(
      `Insufficient get pub key request results, expected ${EXISTING_USER_AUTHENTICATION_THRESHOLD} but got ${completedRequests.length}`,
    );
  }
  const thresholdPubKey = thresholdSame(
    completedRequests.map((res) => res.result?.pubKey),
    EXISTING_USER_AUTHENTICATION_THRESHOLD,
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
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the toprf eval request.
 *
 * @returns - A promise that resolves with the key pair seed successfully.
 */
export const getPubKey = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Record<number, string>;
  verifier: string;
  verifierId: string;
}): Promise<Uint8Array> => {
  const { authTokens, nodeEndpointsMap, verifier, verifierId } = params;

  if (authTokens.length < EXISTING_USER_AUTHENTICATION_THRESHOLD) {
    throw TOPRFError.insufficientAuthTokens(
      `At least ${EXISTING_USER_AUTHENTICATION_THRESHOLD} auth tokens are required.`,
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
        verifier,
        verifierId,
      );
      return sendGetPubKeyRequest(endpoint, requestParams);
    },
  );

  return Some<GetPubKeyJRPCResponse, Uint8Array>(promises, async (resultArr) =>
    validatePubKey(resultArr),
  );
};
