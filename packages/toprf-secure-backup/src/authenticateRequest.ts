import {
  filterCompletedRequests,
  Some,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import {
  EXISTING_USER_AUTHENTICATION_THRESHOLD,
  JRPC_METHODS,
  NEW_USER_AUTHENTICATION_THRESHOLD,
} from './constants';
import { TOPRFError } from './errors';
import type { SingleIdVerifierParams } from './interfaces';
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
 * @param verifierId - The verifierId to be used for the authenticate request
 * @param commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @param singleIdVerifierParams - Optional singleIdVerifierParams to be used for the authenticate request.
 * @returns The parameters for the authenticate JRPC request.
 */
const createAuthenticateRequestParams = (
  idToken: string,
  verifier: string,
  verifierId: string,
  commitmentSignatures: CommitmentRequestResult[],
  singleIdVerifierParams?: SingleIdVerifierParams,
): AuthJRPCRequestParams => {
  const singleIdVerifierParamsArr =
    singleIdVerifierParams?.subVerifierIdTokens &&
    singleIdVerifierParams?.subVerifier
      ? {
          subVerifierAuthParams: [
            {
              subVerifierIdToken: singleIdVerifierParams.subVerifierIdTokens[0],
              subVerifier: singleIdVerifierParams.subVerifier,
            },
          ],
        }
      : undefined;
  return {
    authData: {
      authenticationContext: {
        idToken,
        verifier,
        verifierId,
      },
      singleIdVerifierParams: singleIdVerifierParamsArr,
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
  const completedRequests =
    filterCompletedRequests<AuthJRPCResponse>(resultArr);
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
 * Validates the authenticate responses and waits for the maximum number of requests to complete.
 *
 * @param responses - Authenticate request responses.
 * @param promiseArr - Authenticate request promises.
 * @param startTime - Start time of initiating authenticate requests.
 * @param bufferWaitTime - Buffer wait time to wait for the maximum number of requests to complete even if
 * threshold number of requests is reached.
 *
 * @returns threshold or maximum number of authenticate request results.
 * @throws Error if threshold number of requests is reached but buffer wait time has not elapsed.
 * @throws Error if buffer wait time has elapsed but threshold number of requests is not reached.
 */
export const validateAndWaitForAllAuthResponses = async (
  responses: AuthJRPCResponse[],
  promiseArr: Promise<AuthJRPCResponse>[],
  startTime: number,
  bufferWaitTime: number,
): Promise<{ authRequestResults: AuthRequestResult[]; isNewUser: boolean }> => {
  const result = await validateThresholdAuthenticateResponses(responses);

  // Return immediately if we have all responses
  if (responses.length === promiseArr.length) {
    return result;
  }

  // Return if buffer wait time has elapsed
  if (Date.now() - startTime > bufferWaitTime) {
    return result;
  }

  // Continue waiting by throwing error
  throw new Error(
    'Predicate Error: Threshold achieved, Waiting for maximum number of requests to complete',
  );
};

/**
 * Authenticates the user with the given idToken and verifierId and validates the responses.
 *
 * @param params - The parameters for the authenticate request
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.verifier - The verifier to be used for the authenticate request
 * @param params.verifierId - The verifierId to be used for the authenticate request
 * @param params.sessionPrivateKey - The session private key used for commitment request.
 * @param params.nodeEndpointsMap - The map of node indexes to endpoints map to be used for the authenticate request.
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @param params.singleIdVerifierParams - Optional singleIdVerifierParams to be used for the authenticate request.
 * You can pass this to use aggregate verifier.
 *
 * @returns resultArr - The authenticate request result, where each element is
 * a signed authenticate data from a node and a boolean indicating if the user is new or not.
 */
export const authenticateUser = async (params: {
  idToken: string;
  verifier: string;
  verifierId: string;
  sessionPrivateKey: Uint8Array;
  nodeEndpointsMap: Record<number, string>;
  commitmentSignatures: CommitmentRequestResult[];
  singleIdVerifierParams?: SingleIdVerifierParams;
}): Promise<{
  authTokensData: AuthRequestResult[];
  isNewUser: boolean;
}> => {
  const {
    idToken,
    nodeEndpointsMap,
    verifier,
    verifierId,
    commitmentSignatures,
    sessionPrivateKey,
    singleIdVerifierParams,
  } = params;
  const requestParams = createAuthenticateRequestParams(
    idToken,
    verifier,
    verifierId,
    commitmentSignatures,
    singleIdVerifierParams,
  );
  // start with half the nodes count optimistically.
  const promiseArr = Object.values(nodeEndpointsMap).map(async (endpoint) =>
    sendAuthenticateRequest(endpoint, requestParams),
  );

  // buffer wait time to wait for pending requests to complete even if we have achieved desired threshold.
  const bufferWaitTime = 500;
  const startTime = Date.now();
  const { authRequestResults, isNewUser } = await Some<
    AuthJRPCResponse,
    {
      authRequestResults: AuthRequestResult[];
      isNewUser: boolean;
    }
  >(promiseArr, async (responses) =>
    validateAndWaitForAllAuthResponses(
      responses,
      promiseArr,
      startTime,
      bufferWaitTime,
    ),
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
