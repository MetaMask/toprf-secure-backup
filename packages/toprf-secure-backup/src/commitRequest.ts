import {
  Some,
  keccak256AndHexify,
  filterCompletedRequests,
} from '@metamask/auth-network-utils';
import { utf8ToBytes } from '@noble/hashes/utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { COMMIT_RESPONSE_THRESHOLD, JRPC_METHODS } from './constants';
import { TOPRFError } from './errors';
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
/**
 * Creates a function that handles commitment responses incrementally.
 *
 * @param results - The array of results received so far from Some.
 * @param allSettled - Flag indicating if Some processed all promises.
 * @returns A function that returns the final results array if conditions met, undefined otherwise.
 * Throws TOPRFError if threshold not met after all settled.
 */
export const createHandleCommitmentResponses = (
  results: CommitmentJRPCResponse[],
  allSettled: boolean,
): (() => Promise<CommitmentRequestResult[] | undefined>) => {
  const bufferWaitTime = 1000; // ms
  let thresholdMetTime: number | null = null;

  return async (): Promise<CommitmentRequestResult[] | undefined> => {
    const successfulResults = filterCompletedRequests(results);
    const thresholdMet = successfulResults.length >= COMMIT_RESPONSE_THRESHOLD;

    if (thresholdMet) {
      // Start the timer when the threshold is met
      thresholdMetTime ??= Date.now();
      const bufferElapsed = Date.now() - thresholdMetTime > bufferWaitTime;

      if (allSettled || bufferElapsed) {
        return successfulResults.map(
          (res) => res.result as CommitmentRequestResult,
        );
      }
      return undefined; // Continue waiting
    }

    if (allSettled) {
      // Threshold not met after all settled
      throw TOPRFError.invalidCommitResults(
        `Threshold not met after all requests processed. Expected: ${COMMIT_RESPONSE_THRESHOLD}, got: ${successfulResults.length}`,
      );
    }

    return undefined; // Continue waiting
  };
};

/**
 * Creates a commitment request to the given endpoints and validates the responses using the original Some function.
 *
 * @param params - The parameters for the commitment request
 * @param params.idToken - The idToken to be used for the commitment request
 * @param params.verifier - The verifier to be used for the commitment request
 * @param params.sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param params.sessionPubKeyY - The public key y to be used for the commitment request session.
 * @param params.endpoints - The endpoints to be used for the commitment request
 * @returns resultArr - The commitment request result, where each element is
 * a signed commitment data from a node.
 * @throws SomeError if underlying requests fail significantly (per original Some behavior), or TOPRFError if threshold not met after settling.
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
  const tokenCommitment = keccak256AndHexify(utf8ToBytes(idToken)).slice(2);

  const requestParams = createCommitmentRequestParams(
    tokenCommitment,
    verifier,
    sessionPubKeyX,
    sessionPubKeyY,
  );
  const promiseArr = endpoints.map(async (endpoint) =>
    sendCommitmentRequest(endpoint, requestParams),
  );

  return Some<CommitmentJRPCResponse, CommitmentRequestResult[]>(
    promiseArr,
    async (results, cbParams) =>
      createHandleCommitmentResponses(results, cbParams.allSettled)(),
  );
};
