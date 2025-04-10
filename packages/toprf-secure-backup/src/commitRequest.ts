import {
  Some,
  keccak256AndHexify,
  TOPRFError,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { COMMIT_RESPONSE_THRESHOLD, JRPC_METHODS } from './constants';
import type {
  CommitmentJRPCRequest,
  CommitmentJRPCRequestParams,
  CommitmentJRPCResponse,
  CommitmentRequestResult,
} from './jrpcInterfaces';
import { postJRPCRequest } from './utils';

/**
 * Creates the parameters for the commitment request.
 *
 * @param tokenCommitment - The token commitment, hash of the idToken (without 0x prefix).
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment JRPC request.
 */
const createCommitmentRequestParams = (
  tokenCommitment: string,
  verifier: string,
  sessionPubKeyX: string,
  sessionPubKeyY: string,
): CommitmentJRPCRequestParams => {
  return {
    tokenCommitment,
    verifier,
    tempPubKeyX: sessionPubKeyX,
    tempPubKeyY: sessionPubKeyY,
  };
};

/**
 * Sends a commitment request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the commitment request.
 * @param params - The parameters for the commitment request.
 * @returns The commitment responses.
 */
const sendCommitmentRequest = async (
  endpoint: string,
  params: CommitmentJRPCRequestParams,
): Promise<CommitmentJRPCResponse> => {
  const commitmentJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.COMMITMENT_REQUEST,
    params,
  ) as CommitmentJRPCRequest;

  return postJRPCRequest<CommitmentJRPCResponse>(
    endpoint,
    commitmentJRPCRequest,
  );
};

/**
 * Validates the commitment responses.
 *
 * @param resultArr - The commitment request result.
 * @returns The commitment request result.
 */
export const validateThresholdCommitmentResponses = async (
  resultArr: CommitmentJRPCResponse[],
): Promise<CommitmentRequestResult[]> => {
  const completedRequests = resultArr.filter(
    (res): res is CommitmentJRPCResponse => {
      if (!res || typeof res !== 'object') {
        return false;
      }
      if ('error' in res && res.error) {
        return false;
      }
      return true;
    },
  );

  if (completedRequests.length < COMMIT_RESPONSE_THRESHOLD) {
    throw TOPRFError.invalidCommitResults(
      `Not enough completed requests. Expected: ${COMMIT_RESPONSE_THRESHOLD}, got: ${completedRequests.length}, ${JSON.stringify(resultArr)}`,
    );
  }
  return completedRequests
    .filter((res) => res.result)
    .map((res) => res.result as CommitmentRequestResult);
};

/**
 * Validates the commitment responses and waits for the maximum number of requests to complete before
 * buffer wait time has elapsed or the threshold number of requests is reached after buffer wait time.
 *
 * @param results - Commitment request responses.
 * @param promiseArr - Commitment request promises.
 * @param startTime - Start time of initiating commitment requests.
 * @param bufferWaitTime - Buffer wait time to wait for the maximum number of requests to complete even if
 * threshold number of requests is reached.
 *
 * @returns threshold or maximum number of commitment request results.
 * @throws Error if threshold number of requests is not reached.
 */
export const validateAndWaitForCommitResponses = async (
  results: CommitmentJRPCResponse[],
  promiseArr: Promise<CommitmentJRPCResponse>[],
  startTime: number,
  bufferWaitTime: number,
): Promise<CommitmentRequestResult[]> => {
  const validatedResults = await validateThresholdCommitmentResponses(results);

  // Return immediately if we have all responses
  if (results.length === promiseArr.length) {
    return validatedResults;
  }

  // Return if buffer wait time has elapsed
  if (Date.now() - startTime > bufferWaitTime) {
    return validatedResults;
  }

  // Continue waiting by throwing error
  throw new Error(
    'Predicate Error: Threshold achieved, Waiting for maximum number of requests to complete',
  );
};

/**
 * Creates a commitment request to the given endpoints and validates the responses
 *
 * @param params - The parameters for the commitment request
 * @param params.idToken - The idToken to be used for the commitment request
 * @param params.verifier - The verifier to be used for the commitment request
 * @param params.sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param params.sessionPubKeyY - The public key y to be used for the commitment request session.
 * @param params.endpoints - The endpoints to be used for the commitment request
 * @returns resultArr - The commitment request result, where each element is
 * a signed commitment data from a node.
 */
export const commitIdToken = async (params: {
  idToken: string;
  verifier: string;
  sessionPubKeyX: string;
  sessionPubKeyY: string;
  endpoints: string[];
}): Promise<CommitmentRequestResult[]> => {
  const { idToken, endpoints, verifier, sessionPubKeyX, sessionPubKeyY } =
    params;
  const tokenCommitment = keccak256AndHexify(
    new TextEncoder().encode(idToken),
  ).slice(2);

  const requestParams = createCommitmentRequestParams(
    tokenCommitment,
    verifier,
    sessionPubKeyX,
    sessionPubKeyY,
  );
  const promiseArr = endpoints.map(async (endpoint) =>
    sendCommitmentRequest(endpoint, requestParams),
  );

  const bufferWaitTime = 500;
  const startTime = Date.now();

  return Some<CommitmentJRPCResponse, CommitmentRequestResult[]>(
    promiseArr,
    async (results) =>
      validateAndWaitForCommitResponses(
        results,
        promiseArr,
        startTime,
        bufferWaitTime,
      ),
  );
};
