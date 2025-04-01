import { Some, thresholdSame } from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type {
  AuthJRPCRequest,
  AuthJRPCResponse,
  AuthJRPCRequestParams,
  CommitmentRequestResult,
  AuthRequestResult,
} from './jrpcInterfaces';
import { decryptAuthToken, postJRPCRequest } from './utils';

/**
 * Creates the parameters for the authenticate request
 *
 * @param idToken - The idToken to be used for the authenticate request
 * @param verifier - The verifier to be used for the authenticate request
 * @param verifierID - The verifierID to be used for the authenticate request
 * @param commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 *
 * @returns The parameters for the authenticate jrpc request.
 */
const createAuthenticateRequestParams = (
  idToken: string,
  verifier: string,
  verifierID: string,
  commitmentSignatures: CommitmentRequestResult[],
): AuthJRPCRequestParams => {
  return {
    authData: {
      authenticationContext: {
        idToken,
        verifier,
        verifierId: verifierID,
      },
    },
    commitmentSignatures,
    clientTime: Math.floor(Date.now() / 1000).toString(),
  };
};

/**
 * Sends an authenticate request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @returns The authenticate request promise.
 */
const sendAuthenticateRequest = async (
  endpoint: string,
  params: AuthJRPCRequestParams,
): Promise<AuthJRPCResponse> => {
  const authJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.AUTHENTICATE_REQUEST,
    params,
  ) as AuthJRPCRequest;
  return postJRPCRequest<AuthJRPCResponse>(endpoint, authJRPCRequest);
};

/**
 * Validates the authenticate responses.
 *
 * @param resultArr - The authenticate request result
 * @param nodesCount - The number of nodes.
 * @returns The authenticate request result
 */
const validateThresholdAuthenticateResponses = (
  resultArr: AuthJRPCResponse[],
  nodesCount: number,
): AuthRequestResult[] => {
  // start with half the nodes count optimistically.
  const threshold = Math.floor(nodesCount / 2) + 1;

  const completedRequests = resultArr.filter((res): res is AuthJRPCResponse => {
    if (!res || typeof res !== 'object') {
      return false;
    }
    if ('error' in res && res.error) {
      return false;
    }
    return true;
  });

  if (completedRequests.length < threshold) {
    throw new Error(
      `Not enough completed requests. Expected: ${threshold}, got: ${completedRequests.length}`,
    );
  }

  const pubData = completedRequests.map((res: AuthJRPCResponse) => {
    const result = res.result as AuthRequestResult;
    return {
      pubKey: result.pubKey,
      keyIndex: result.keyIndex,
    };
  });
  const thresholdPubData = thresholdSame(pubData, threshold);
  if (!thresholdPubData) {
    throw new Error(`Not enough matching pubData.`);
  }

  // if it is new user then we need all the responses because we will need all
  // nodes to be online while storing shares of this new user.
  const newUser = !thresholdPubData.pubKey;
  const hasMaxResponses = nodesCount === completedRequests.length;
  if (newUser && !hasMaxResponses) {
    throw new Error(
      `Not enough completed requests. Expected: ${nodesCount}, got: ${completedRequests.length}`,
    );
  }

  return completedRequests.map((res) => res.result as AuthRequestResult);
};

/**
 * Authenticates the user with the given idToken and verifierID and validates the responses.
 *
 * @param params - The parameters for the authenticate request
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.verifier - The verifier to be used for the authenticate request
 * @param params.verifierID - The verifierID to be used for the authenticate request
 * @param params.sessionPrivateKey - The session private key used for commitment request.
 * @param params.endpoints - The endpoints to be used for the authenticate request
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @returns resultArr - The authenticate request result, where each element is
 * a signed authenticate data from a node.
 */
export const authenticateUser = async (params: {
  idToken: string;
  verifier: string;
  verifierID: string;
  sessionPrivateKey: string;
  endpoints: string[];
  commitmentSignatures: CommitmentRequestResult[];
}): Promise<AuthRequestResult[]> => {
  const {
    idToken,
    endpoints,
    verifier,
    verifierID,
    commitmentSignatures,
    sessionPrivateKey,
  } = params;
  const requestParams = createAuthenticateRequestParams(
    idToken,
    verifier,
    verifierID,
    commitmentSignatures,
  );
  const promiseArr = endpoints.map(async (endpoint) =>
    sendAuthenticateRequest(endpoint, requestParams),
  );

  const results = await Some<AuthJRPCResponse, AuthRequestResult[]>(
    promiseArr,
    async (responses) =>
      validateThresholdAuthenticateResponses(responses, endpoints.length),
  );

  if (!results || results.length === 0) {
    throw new Error('Invalid authenticate request results');
  }

  const decryptedAuthResults = await Promise.all(
    results.map(async (result) => {
      const { authToken, nodeIndex, nodePubKey, pubKey, keyIndex } = result;
      const decryptedAuthToken = await decryptAuthToken(
        authToken,
        sessionPrivateKey,
      );
      return {
        authToken: decryptedAuthToken,
        nodeIndex,
        nodePubKey,
        pubKey,
        keyIndex,
      };
    }),
  );
  return decryptedAuthResults;
};
