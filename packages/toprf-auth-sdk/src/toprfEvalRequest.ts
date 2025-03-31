import {
  Some,
  kCombinations,
  lagrangeInterpolationForPoints,
  pubKeyToSec1,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { secp256k1 } from 'ethereum-cryptography/secp256k1';

import { JRPC_METHODS } from './constants';
import type { NodeAuthTokens } from './interfaces';
import type {
  ToprfEvalJRPCRequest,
  ToprfEvalJRPCRequestParams,
  ToprfEvalJRPCResponse,
} from './jrpcInterfaces';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF } from './oprf';
import { postJRPCRequest } from './utils';

type BlindedPoint = {
  x: string;
  y: string;
  nodeIndex: number;
};
/**
 * Creates the parameters for the toprf eval request
 *
 * @param authToken - The auth issued by node to authenticate the request.
 * @param blindedInputX - The blinded input x.
 * @param blindedInputY - The blinded input y.
 * @param verifier - The verifier name.
 * @param verifierId - The verifier id of the user.
 *
 * @returns The parameters for the toprf eval jrpc request.
 */
export const createToprfEvalRequestParams = (
  authToken: string,
  blindedInputX: string,
  blindedInputY: string,
  verifier: string,
  verifierId: string,
): ToprfEvalJRPCRequestParams => {
  return {
    authToken,
    shareCoefficient: '1',
    blindedInputX,
    blindedInputY,
    verifier,
    verifierId,
  };
};

/**
 * Creates a toprf eval request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the toprf eval request
 * @param params - The parameters for the toprf eval request
 * @returns Array of toprf eval request promises
 */
export const createToprfEvalRequest = async (
  endpoint: string,
  params: ToprfEvalJRPCRequestParams,
): Promise<ToprfEvalJRPCResponse> => {
  const toprfEvalJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.TOPRF_EVAL_REQUEST,
    params,
  ) as ToprfEvalJRPCRequest;
  /**
   * Sends the toprf eval request to the given endpoint and returns the toprf eval response.
   *
   * @returns The toprf eval response.
   */
  const toprfEvalResponse = postJRPCRequest<ToprfEvalJRPCResponse>(
    endpoint,
    toprfEvalJRPCRequest,
  );

  return toprfEvalResponse;
};

/**
 * Evaluates the seed from the toprf eval responses
 *
 * @param hashedInput - The hashed input i.e. hash of the password.
 * @param randomScalar - The random scalar used to blind the input.
 * @param resultArr - The toprf eval request result
 * @param threshold - Mininum number of valid responses required to evaluate key using toprf.
 * @returns The toprf eval request result
 */
export const evaluateSeed = async (
  hashedInput: Uint8Array,
  randomScalar: bigint,
  resultArr: ToprfEvalJRPCResponse[],
  threshold: number,
): Promise<Uint8Array> => {
  const completedRequests = resultArr.filter(
    (res): res is ToprfEvalJRPCResponse => {
      if (!res || typeof res !== 'object') {
        return false;
      }
      if ('error' in res && res.error) {
        return false;
      }
      return true;
    },
  );

  if (completedRequests.length >= threshold) {
    const thresholdAuthPubKey = thresholdSame(
      completedRequests.map((res) => res.result?.pubKey),
      threshold,
    );
    if (thresholdAuthPubKey) {
      const blindedServerPoints = completedRequests
        .map((resp): BlindedPoint | null => {
          const { blindedOutputX, blindedOutputY, nodeIndex } =
            resp.result ?? {};

          // Check if all required values are defined
          if (!blindedOutputX || !blindedOutputY || !nodeIndex) {
            return null;
          }

          return {
            x: blindedOutputX,
            y: blindedOutputY,
            nodeIndex,
          };
        })
        .filter((point): point is BlindedPoint => point !== null);

      // evaluate auth priv key using oprf and match with the threshold auth pub key
      const allCombis = kCombinations(completedRequests.length, threshold);
      let seed: Uint8Array | null = null;
      for (const currentCombi of allCombis) {
        const currentCombiPoints = blindedServerPoints.filter((_, index) =>
          currentCombi.includes(index),
        );

        const curvePoints = currentCombiPoints.map((point) =>
          secp256k1.ProjectivePoint.fromHex(`04${point.x}${point.y}`),
        );

        const nodeIndexes = currentCombiPoints.map((point) =>
          BigInt(point.nodeIndex),
        );
        // Interpolate the curve points directly using Lagrange interpolation
        const reconstructedPoint = lagrangeInterpolationForPoints(
          secp256k1.CURVE.n,
          curvePoints,
          nodeIndexes,
        );

        // Unblind and hash the result
        const recoveredSeed = OPRF.unblindAndHash(
          hashedInput,
          reconstructedPoint,
          randomScalar,
        );

        const { pk } = deriveAuthenticationKeyPair(recoveredSeed);
        const authPubKey = pubKeyToSec1(pk);
        if (authPubKey === thresholdAuthPubKey) {
          seed = recoveredSeed;
          break;
        }
      }

      if (!seed) {
        throw new Error('could not derive encryption key');
      }

      return Promise.resolve(seed);
    }
  }

  return Promise.reject(
    new Error(`invalid toprf eval results ${JSON.stringify(resultArr)}`),
  );
};

/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.endpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 *
 * @param params.password - The password of the user.
 * @returns - A promise that resolves with the key pair seed successfully.
 */
export const recoverTOPRFSeed = async (params: {
  authTokens: NodeAuthTokens;
  endpointsMap: Record<number, string>;
  verifier: string;
  verifierId: string;
  password: string;
}): Promise<Uint8Array> => {
  const { authTokens, endpointsMap, verifier, verifierId, password } = params;

  if (authTokens.length === 0) {
    throw new Error('No auth tokens provided');
  }

  if (Object.keys(endpointsMap).length === 0) {
    throw new Error('No endpoints provided');
  }

  if (authTokens.length < 3) {
    throw new Error('At least 3 auth tokens are required');
  }

  const passwordBytes = new TextEncoder().encode(password);
  const hashedInput = keccak256(passwordBytes);
  const { a, r } = OPRF.blind(hashedInput);
  const promiseArr = authTokens.map(async (authToken) => {
    const endpoint = endpointsMap[authToken.nodeIndex];
    if (!endpoint) {
      throw new Error(
        `Endpoint not found for node index ${authToken.nodeIndex}`,
      );
    }
    const requestParams = createToprfEvalRequestParams(
      authToken.authToken,
      a.x.toString(16),
      a.y.toString(16),
      verifier,
      verifierId,
    );
    return createToprfEvalRequest(endpoint, requestParams);
  });

  const result = await Some<ToprfEvalJRPCResponse, Uint8Array>(
    promiseArr,
    async (resultArr) =>
      evaluateSeed(hashedInput, r, resultArr, authTokens.length),
  );

  if (!result) {
    throw new Error('Insufficient toprf eval request results');
  }

  return result;
};
