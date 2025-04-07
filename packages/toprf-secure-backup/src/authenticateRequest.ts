import { Some, thresholdSame, TOPRFError } from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import {
  EXISTING_USER_AUTHENTICATION_THRESHOLD,
  JRPC_METHODS,
  NEW_USER_AUTHENTICATION_THRESHOLD,
} from './constants';
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
 * @param verifier - The verifier
 * to be used for the authenticate request
 * @param verifierID - The verifierID to be used for the authenticate request
 * @param commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 *
 * @returns The parameters for the authenticate JRPC request.
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
 * Validates the authenticate responses
 *
 * @param resultArr - The authenticate request result
 * @returns The authenticate request result and a boolean indicating if the user is new or not.
 */
export const validateThresholdAuthenticateResponses = async (
  resultArr: AuthJRPCResponse[],
): Promise<{
  authRequestResults: AuthRequestResult[];
  isNewUser: boolean;
}> => {
  const completedRequests = resultArr.filter((res): res is AuthJRPCResponse => {
    if (!res || typeof res !== 'object') {
      return false;
    }
    if ('error' in res && res.error) {
      return false;
    }
    return true;
  });
  if (completedRequests.length < EXISTING_USER_AUTHENTICATION_THRESHOLD) {
    throw TOPRFError.invalidAuthenticateResults(
      `Not enough completed requests. Expected: ${EXISTING_USER_AUTHENTICATION_THRESHOLD}, got: ${completedRequests.length}`,
    );
  }
  const pubData = completedRequests.map((res: AuthJRPCResponse) => {
    const result = res.result as AuthRequestResult;
    return {
      pubKey: result.pubKey,
      keyIndex: result.keyIndex,
    };
  });
  const thresholdPubData = thresholdSame(
    pubData,
    EXISTING_USER_AUTHENTICATION_THRESHOLD,
  );
  if (!thresholdPubData) {
    throw TOPRFError.invalidAuthenticateResults(
      `Threshold pubKey not found for ${JSON.stringify(pubData)}`,
    );
  }
  const isNewUser = !thresholdPubData.pubKey;
  const hasMaxResponses =
    completedRequests.length >= NEW_USER_AUTHENTICATION_THRESHOLD;

  // if it is new user then we need to wait for all the responses because we will need all nodes to be online
  // while storing shares of this new user.
  if (isNewUser && !hasMaxResponses) {
    throw TOPRFError.invalidAuthenticateResults(
      `Not enough completed requests. Expected: ${NEW_USER_AUTHENTICATION_THRESHOLD}, got: ${completedRequests.length}`,
    );
  }
  return {
    authRequestResults: completedRequests.map(
      (res) => res.result as AuthRequestResult,
    ),
    isNewUser,
  };
};

/**
 * Authenticates the user with the given idToken and verifierID and validates the responses.
 *
 * @param params - The parameters for the authenticate request
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.verifier - The verifier to be used for the authenticate request
 * @param params.verifierID - The verifierID to be used for the authenticate request
 * @param params.sessionPrivateKey - The session private key used for commitment request.
 * @param params.nodeEndpointsMap - The map of node indexes to endpoints map to be used for the authenticate request.
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @returns resultArr - The authenticate request result, where each element is
 * a signed authenticate data from a node and a boolean indicating if the user is new or not.
 */
export const authenticateUser = async (params: {
  idToken: string;
  verifier: string;
  verifierID: string;
  sessionPrivateKey: Uint8Array;
  nodeEndpointsMap: Record<number, string>;
  commitmentSignatures: CommitmentRequestResult[];
}): Promise<{
  authTokensData: AuthRequestResult[];
  isNewUser: boolean;
}> => {
  const {
    idToken,
    nodeEndpointsMap,
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
  // start with half the nodes count optimistically.
  const promiseArr = Object.values(nodeEndpointsMap).map(async (endpoint) =>
    sendAuthenticateRequest(endpoint, requestParams),
  );

  const { authRequestResults, isNewUser } = await Some<
    AuthJRPCResponse,
    {
      authRequestResults: AuthRequestResult[];
      isNewUser: boolean;
    }
  >(promiseArr, async (responses: AuthJRPCResponse[]) =>
    validateThresholdAuthenticateResponses(responses),
  );

  const decryptedAuthResults = await Promise.all(
    authRequestResults.map(async (result: AuthRequestResult) => {
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
  return {
    authTokensData: decryptedAuthResults,
    isNewUser,
  };
};
