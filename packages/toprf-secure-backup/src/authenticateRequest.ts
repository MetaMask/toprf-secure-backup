import {
  filterCompletedRequests,
  Some,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { AUTHENTICATION_THRESHOLD, JRPC_METHODS } from './constants';
import { TOPRFError, TOPRFErrorCode } from './errors';
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
 * @param params - The parameters for creating the authenticate request parameters
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.authConnectionId - The auth connection name to be used for the authenticate request
 * @param params.userId - The userId to be used for the authenticate request
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @param params.groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request.
 * @param params.hashedIdToken - Optional hashed idToken to be used for the authenticate request when using aggregate verifier.
 * @returns The parameters for the authenticate JRPC request.
 */
const createAuthenticateRequestParams = (params: {
  idToken: string;
  authConnectionId: string;
  userId: string;
  commitmentSignatures: CommitmentRequestResult[];
  groupedAuthConnectionId?: string;
  hashedIdToken?: string;
}): AuthJRPCRequestParams => {
  const singleIdVerifierParams = params.groupedAuthConnectionId
    ? {
        subVerifierAuthParams: [
          {
            subVerifierIdToken: params.idToken,
            subVerifier: params.authConnectionId,
          },
        ],
      }
    : undefined;

  // hashedIdToken must be present when using aggregate verifier (i.e. groupedAuthConnectionId is present)
  if (params.groupedAuthConnectionId && !params.hashedIdToken) {
    throw TOPRFError.fromCode(TOPRFErrorCode.NoHashedIdToken);
  }

  const idToken =
    params.groupedAuthConnectionId && params.hashedIdToken
      ? params.hashedIdToken
      : params.idToken;

  return {
    authData: {
      authenticationContext: {
        idToken,
        verifier: params.groupedAuthConnectionId ?? params.authConnectionId,
        verifierId: params.userId,
      },
      singleIdVerifierParams,
    },
    commitmentSignatures: params.commitmentSignatures,
    clientTime: Math.floor(Date.now() / 1000).toString(),
  };
};

/**
 * Sends an authenticate request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @param clientIdentifier - Optional client identifier sent as the `x-web3-client` header.
 * @returns The authenticate request promise.
 */
const sendAuthenticateRequest = async (
  endpoint: string,
  params: AuthJRPCRequestParams,
  clientIdentifier?: string,
): Promise<AuthJRPCResponse> => {
  const authJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.AUTHENTICATE_REQUEST,
    params,
  ) as AuthJRPCRequest;
  return postJRPCRequest<AuthJRPCResponse>(
    endpoint,
    authJRPCRequest,
    clientIdentifier,
  );
};

/**
 * Creates a function that handles authenticate responses incrementally.
 *
 * @param results - The array of results received so far from Some.
 * @param allSettled - Flag indicating if Some processed all promises.
 * @returns A function that returns the final validation result if conditions met, undefined otherwise.
 * Throws TOPRFError if threshold not met or data inconsistent.
 */
export const createAuthResponseHandler = (
  results: AuthJRPCResponse[],
  allSettled: boolean,
): (() => Promise<
  { authRequestResults: AuthRequestResult[]; isNewUser: boolean } | undefined
>) => {
  const bufferWaitTime = 1000;
  let thresholdMetTime: number | null = null;

  return async (): Promise<
    { authRequestResults: AuthRequestResult[]; isNewUser: boolean } | undefined
  > => {
    const completedRequests = filterCompletedRequests(results);
    const thresholdMet = completedRequests.length >= AUTHENTICATION_THRESHOLD;

    if (thresholdMet) {
      // Start the timer when the threshold is met
      thresholdMetTime ??= Date.now();
      const bufferElapsed = Date.now() - thresholdMetTime > bufferWaitTime;

      if (allSettled || bufferElapsed) {
        // Check consistency of pubKey/keyIndex data
        const pubData = completedRequests.map((res: AuthJRPCResponse) => {
          const { pubKey, keyIndex } = res.result as AuthRequestResult;
          return { pubKey, keyIndex };
        });
        const thresholdPubData = thresholdSame(
          pubData,
          AUTHENTICATION_THRESHOLD,
        );

        if (!thresholdPubData) {
          throw TOPRFError.invalidAuthenticateResults(
            `Authentication threshold met, but pubKey/keyIndex data inconsistent: ${JSON.stringify(pubData)}`,
          );
        }

        return {
          authRequestResults: completedRequests.map(
            (res) => res.result as AuthRequestResult,
          ),
          isNewUser: !thresholdPubData.pubKey,
        };
      }
      return undefined; // Continue waiting
    }

    if (allSettled) {
      // Threshold not met after all settled
      throw TOPRFError.invalidAuthenticateResults(
        `Authentication threshold not met after all requests processed. Expected: ${AUTHENTICATION_THRESHOLD}, got: ${completedRequests.length}`,
      );
    }

    return undefined; // Continue waiting
  };
};

/**
 * Authenticates the user with the given id token and user id and validates the responses.
 *
 * @param params - The parameters for the authenticate request
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.authConnectionId - The auth connection name to be used for the authenticate request
 * @param params.groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request
 * @param params.hashedIdToken - Optional hashed idToken to be used for the authenticate request when using aggregate verifier.
 * @param params.userId - The user id of the user to be used for the authenticate request
 * @param params.sessionPrivateKey - The session private key used for commitment request.
 * @param params.nodeEndpointsMap - The map of node indexes to endpoints map to be used for the authenticate request.
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * You can pass this to use aggregate verifier.
 * @param params.clientIdentifier - Optional client identifier sent as the `x-web3-client` header.
 *
 * @returns resultArr - The authenticate request result, where each element is
 * a signed authenticate data from a node and a boolean indicating if the user is new or not.
 * @throws SomeError if underlying requests fail significantly, or TOPRFError if threshold cannot be met or data is inconsistent.
 */
export const authenticateUser = async (params: {
  idToken: string;
  authConnectionId: string;
  userId: string;
  sessionPrivateKey: Uint8Array;
  nodeEndpointsMap: Record<number, string>;
  commitmentSignatures: CommitmentRequestResult[];
  groupedAuthConnectionId?: string;
  hashedIdToken?: string;
  clientIdentifier?: string;
}): Promise<{
  authTokensData: AuthRequestResult[];
  isNewUser: boolean;
}> => {
  const {
    idToken,
    nodeEndpointsMap,
    authConnectionId,
    userId,
    commitmentSignatures,
    groupedAuthConnectionId,
    hashedIdToken,
    sessionPrivateKey,
    clientIdentifier,
  } = params;
  const requestParams = createAuthenticateRequestParams({
    idToken,
    authConnectionId,
    userId,
    commitmentSignatures,
    groupedAuthConnectionId,
    hashedIdToken,
  });

  const endpoints = Object.values(nodeEndpointsMap);
  const promiseArr = endpoints.map(async (endpoint) =>
    sendAuthenticateRequest(endpoint, requestParams, clientIdentifier),
  );

  const validationResult = await Some<
    AuthJRPCResponse,
    {
      authRequestResults: AuthRequestResult[];
      isNewUser: boolean;
    }
  >(promiseArr, async (results, cbParams) =>
    createAuthResponseHandler(results, cbParams.allSettled)(),
  );

  // Decrypt results after successful validation
  const decryptedAuthResults = await Promise.all(
    validationResult.authRequestResults.map(
      async (result: AuthRequestResult) => {
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
      },
    ),
  );
  return {
    authTokensData: decryptedAuthResults,
    isNewUser: validationResult.isNewUser,
  };
};
