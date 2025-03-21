import {
  Some,
  keccak256AndHexify,
  retryPromiseWithBackoff,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject, post } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type {
  CommitmentJRPCRequest,
  CommitmentJRPCRequestParams,
  CommitmentJRPCResponse,
  CommitmentRequestResult,
} from './jrpcInterfaces';

/**
 * Creates the parameters for the commitment request
 *
 * @param tokenCommitment - The token commitment, hash of the idToken
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment jrpc request
 */
export const createCommitmentRequestParams = (
  tokenCommitment: string,
  verifier: string,
  sessionPubKeyX: string,
  sessionPubKeyY: string,
): CommitmentJRPCRequestParams => {
  return {
    message_prefix: 'mug00',
    token_commitment: tokenCommitment.slice(2),
    verifier,
    temp_pub_key_x: sessionPubKeyX,
    temp_pub_key_y: sessionPubKeyY,
  };
};

/**
 * Creates a commitment request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the commitment request
 * @param params - The parameters for the commitment request
 * @returns Array of commitment request promises
 */
export const createCommitmentRequest = (
  endpoint: string,
  params: CommitmentJRPCRequestParams,
): Promise<CommitmentJRPCResponse> => {
  const commitmentJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.COMMITMENT_REQUEST,
    params,
  ) as CommitmentJRPCRequest;
  const p = () =>
    post<CommitmentJRPCResponse>(
      endpoint,
      commitmentJRPCRequest,
      {},
      { logTracingHeader: false },
    );
  return retryPromiseWithBackoff(p, 4);
};

/**
 * Validates the commitment responses
 *
 * @param resultArr - The commitment request result
 * @param threeFourthsThreshold - The threshold for the number commitment responses to be valid
 * @returns The commitment request result
 */
export const validateThresholdCommitmentResponses = (
  resultArr: CommitmentJRPCResponse[],
  threeFourthsThreshold: number,
): Promise<CommitmentRequestResult[]> => {
  const completedRequests = resultArr.filter(
    (x): x is CommitmentJRPCResponse => {
      if (!x || typeof x !== 'object') {
        return false;
      }
      if ('error' in x && x.error) {
        return false;
      }
      return true;
    },
  );

  if (completedRequests.length >= threeFourthsThreshold) {
    const requiredNodeResult = completedRequests.find(
      (resp) => resp !== undefined && 'result' in resp,
    );
    if (requiredNodeResult) {
      const validResultArr = completedRequests.filter((x) => x.result);
      return Promise.resolve(
        validResultArr.map((x) => x.result as CommitmentRequestResult),
      );
    }
  }

  return Promise.reject(
    new Error(`invalid commitment results ${JSON.stringify(resultArr)}`),
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
 * @param params.indexes - The indexes to be used for the commitment request
 * @returns resultArr - The commitment request result, where each element is
 * a signed commitment data from a node.
 */
export const commitmentRequest = async (params: {
  idToken: string;
  verifier: string;
  sessionPubKeyX: string;
  sessionPubKeyY: string;
  endpoints: string[];
  indexes: number[];
}): Promise<CommitmentRequestResult[]> => {
  const { idToken, endpoints, verifier, sessionPubKeyX, sessionPubKeyY } =
    params;
  const threeFourthsThreshold = Math.floor((endpoints.length * 3) / 4) + 1;
  const tokenCommitment = keccak256AndHexify(Buffer.from(idToken, 'utf8'));

  const requestParams = createCommitmentRequestParams(
    tokenCommitment,
    verifier,
    sessionPubKeyX,
    sessionPubKeyY,
  );
  const promiseArr = endpoints.map((endpoint) =>
    createCommitmentRequest(endpoint, requestParams),
  );

  return new Promise<CommitmentRequestResult[]>((resolve, reject) => {
    Some<CommitmentJRPCResponse, CommitmentRequestResult[]>(
      promiseArr,
      (resultArr) =>
        validateThresholdCommitmentResponses(resultArr, threeFourthsThreshold),
    )
      .then((resultArr: CommitmentRequestResult[]) => {
        if (!resultArr || resultArr.length === 0) {
          throw new Error('No commitment request results');
        } else {
          return resolve(resultArr);
        }
      })
      .catch(reject);
  });
};
