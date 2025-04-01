import {
  Some,
  keccak256AndHexify,
  retryPromiseWithBackoff,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type {
  CommitmentJRPCRequest,
  CommitmentJRPCRequestParams,
  CommitmentJRPCResponse,
  CommitmentRequestResult,
} from './jrpcInterfaces';
import { postJRPCRequest } from './utils';

/**
 * Creates the parameters for a commitment request.
 *
 * @param tokenCommitment - The token commitment, hash of the idToken
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment jrpc request
 */
const createCommitmentRequestParams = (
  tokenCommitment: string,
  verifier: string,
  sessionPubKeyX: string,
  sessionPubKeyY: string,
): CommitmentJRPCRequestParams => {
  return {
    messagePrefix: 'mug00',
    tokenCommitment: tokenCommitment.slice(2),
    verifier,
    tempPubKeyX: sessionPubKeyX,
    tempPubKeyY: sessionPubKeyY,
  };
};

/**
 * Sends a commitment request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the commitment request
 * @param params - The parameters for the commitment request
 * @returns Array of commitment request promises
 */
const sendCommitmentRequest = async (
  endpoint: string,
  params: CommitmentJRPCRequestParams,
): Promise<CommitmentJRPCResponse> => {
  const commitmentJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.COMMITMENT_REQUEST,
    params,
  ) as CommitmentJRPCRequest;
  return retryPromiseWithBackoff(async () => {
    return postJRPCRequest<CommitmentJRPCResponse>(
      endpoint,
      commitmentJRPCRequest,
    );
  }, 4);
};

/**
 * Validates the commitment responses
 *
 * @param resultArr - The commitment request result
 * @param threshold - The threshold for the number commitment responses to be valid
 * @returns The commitment request result
 */
const validateThresholdCommitmentResponses = (
  resultArr: CommitmentJRPCResponse[],
  threshold: number,
): CommitmentRequestResult[] => {
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

  if (completedRequests.length < threshold) {
    throw new Error(
      `not enough commitment responses, got ${completedRequests.length} but expected at least ${threshold}`,
    );
  }

  const requiredNodeResult = completedRequests.find(
    (resp) => resp !== undefined && 'result' in resp,
  );
  if (!requiredNodeResult) {
    throw new Error('no valid commitment response');
  }

  const validResultArr = completedRequests.filter((res) => res.result);
  return validResultArr.map((res) => res.result as CommitmentRequestResult);
};

/**
 * Sends a commitment request to the given endpoints and validates the responses.
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
  const threshold = Math.floor((endpoints.length * 3) / 4) + 1;
  const tokenCommitment = keccak256AndHexify(new TextEncoder().encode(idToken));

  const requestParams = createCommitmentRequestParams(
    tokenCommitment,
    verifier,
    sessionPubKeyX,
    sessionPubKeyY,
  );
  const promiseArr = endpoints.map(async (endpoint) =>
    sendCommitmentRequest(endpoint, requestParams),
  );

  const resultArr = await Some<
    CommitmentJRPCResponse,
    CommitmentRequestResult[]
  >(promiseArr, async (results: CommitmentJRPCResponse[]) =>
    validateThresholdCommitmentResponses(results, threshold),
  );

  if (!resultArr || resultArr.length === 0) {
    throw new Error('No commitment request results');
  }

  return resultArr;
};
