import { Some, thresholdSame } from '@metamask/auth-network-utils';
import { generateJsonRPCObject, post } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type {
  AuthJRPCRequest,
  AuthJRPCResponse,
  AuthJRPCRequestParams,
  CommitmentRequestResult,
  AuthRequestResult,
} from './jrpcInterfaces';

/**
 * Creates the parameters for the authenticate request
 *
 * @param idToken - The idToken to be used for the authenticate request
 * @param verifier - The verifier to be used for the authenticate request
 * @param verifierID - The verifierID to be used for the authenticate request
 * @param commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 *
 * @returns The parameters for the authenticate jrpc request
 */
export const createAuthenticateRequestParams = (
  idToken: string,
  verifier: string,
  verifierID: string,
  commitmentSignatures: CommitmentRequestResult[],
): AuthJRPCRequestParams => {
  return {
    auth_data: {
      authentication_context: {
        id_token: idToken,
        verifier,
        verifier_id: verifierID,
      },
      verifier_oauth_params: {},
    },
    commitment_signatures: commitmentSignatures,
    client_time: Math.floor(Date.now() / 1000).toString(),
  };
};

/**
 * Creates a authenticate request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @returns The authenticate request promise.
 */
export const createAuthenticateRequest = (
  endpoint: string,
  params: AuthJRPCRequestParams,
): Promise<AuthJRPCResponse> => {
  const authJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.AUTHENTICATE_REQUEST,
    params,
  ) as AuthJRPCRequest;
  const p = () =>
    post<AuthJRPCResponse>(
      endpoint,
      authJRPCRequest,
      {},
      { logTracingHeader: false },
    );
  return p();
};

/**
 * Validates the authenticate responses
 *
 * @param resultArr - The authenticate request result
 * @param threshold - The threshold for the number authenticate responses to be valid
 * @returns The authenticate request result
 */
export const validateThresholdAuthenticateResponses = (
  resultArr: AuthJRPCResponse[],
  threshold: number,
): Promise<AuthRequestResult[]> => {
  const completedRequests = resultArr.filter((x): x is AuthJRPCResponse => {
    if (!x || typeof x !== 'object') {
      return false;
    }
    if ('error' in x && x.error) {
      return false;
    }
    return true;
  });
  if (completedRequests.length >= threshold) {
    const pubkeys = completedRequests.map((x) => {
      if (x && x.result && x.result.enc_pub_key) {
        return x.result.enc_pub_key;
      }
      return undefined;
    });
    const existingPubKey = thresholdSame(pubkeys, threshold);
    if (existingPubKey) {
      return Promise.resolve(
        completedRequests.map((x) => x.result as AuthRequestResult),
      );
    }
  }

  return Promise.reject(
    new Error(`invalid authenticate results ${JSON.stringify(resultArr)}`),
  );
};

/**
 * Creates a authenticate request to the given endpoints and validates the responses
 *
 * @param params - The parameters for the authenticate request
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.verifier - The verifier to be used for the authenticate request
 * @param params.verifierID - The verifierID to be used for the authenticate request
 * @param params.endpoints - The endpoints to be used for the authenticate request
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @returns resultArr - The authenticate request result, where each element is
 * a signed authenticate data from a node.
 */
export const authenticateRequest = async (params: {
  idToken: string;
  verifier: string;
  verifierID: string;
  endpoints: string[];
  commitmentSignatures: CommitmentRequestResult[];
}): Promise<AuthRequestResult[]> => {
  const { idToken, endpoints, verifier, verifierID, commitmentSignatures } =
    params;
  const halfThreshold = Math.floor(endpoints.length / 2) + 1;
  const requestParams = createAuthenticateRequestParams(
    idToken,
    verifier,
    verifierID,
    commitmentSignatures,
  );
  const promiseArr = endpoints.map((endpoint) =>
    createAuthenticateRequest(endpoint, requestParams),
  );

  return new Promise<AuthRequestResult[]>((resolve, reject) => {
    Some<AuthJRPCResponse, AuthRequestResult[]>(promiseArr, (resultArr) =>
      validateThresholdAuthenticateResponses(resultArr, halfThreshold),
    )
      .then((resultArr: AuthRequestResult[]) => {
        if (!resultArr || resultArr.length === 0) {
          throw new Error('Invalid authenticate request results');
        } else {
          return resolve(resultArr);
        }
      })
      .catch(reject);
  });
};
