import {
  Some,
  kCombinations,
  lagrangeInterpolationForPoints,
  thresholdSame,
} from '@metamask/auth-network-utils';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import {
  EXISTING_USER_AUTHENTICATION_THRESHOLD,
  JRPC_METHODS,
} from './constants';
import type { NodeAuthTokens } from './interfaces';
import type {
  ToprfEvalJRPCRequest,
  ToprfEvalJRPCRequestParams,
  ToprfEvalJRPCResponse,
} from './jrpcInterfaces';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF } from './oprf';
import { postJRPCRequest } from './utils';

type BlindedOutputShare = {
  blindedOutput: ProjPointType<bigint>;
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
 * Sends a toprf eval request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the toprf eval request
 * @param params - The parameters for the toprf eval request
 * @returns Array of toprf eval request promises
 */
const sendToprfEvalRequest = async (
  endpoint: string,
  params: ToprfEvalJRPCRequestParams,
): Promise<ToprfEvalJRPCResponse> => {
  const toprfEvalJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.TOPRF_EVAL_REQUEST,
    params,
  ) as ToprfEvalJRPCRequest;

  return postJRPCRequest<ToprfEvalJRPCResponse>(endpoint, toprfEvalJRPCRequest);
};

/**
 * Evaluates the seed from the toprf eval responses
 *
 * @param hashedInput - The hashed input i.e. hash of the password.
 * @param randomScalar - The random scalar used to blind the input.
 * @param resultArr - The toprf eval request result
 * @returns The toprf eval request result
 */
export const evaluateSeed = async (
  hashedInput: Uint8Array,
  randomScalar: bigint,
  resultArr: ToprfEvalJRPCResponse[],
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

  if (completedRequests.length < EXISTING_USER_AUTHENTICATION_THRESHOLD) {
    return Promise.reject(
      new Error(
        `Insufficient toprf eval request results, expected ${EXISTING_USER_AUTHENTICATION_THRESHOLD} but got ${completedRequests.length}`,
      ),
    );
  }
  const thresholdAuthPubKey = thresholdSame(
    completedRequests.map((res) => res.result?.pubKey),
    EXISTING_USER_AUTHENTICATION_THRESHOLD,
  );

  if (!thresholdAuthPubKey) {
    return Promise.reject(new Error('could not derive threshold auth pub key'));
  }

  const blindedServerPoints = completedRequests
    .map((resp): BlindedOutputShare | null => {
      const { blindedOutputX, blindedOutputY, nodeIndex } = resp.result ?? {};

      // Check if all required values are defined
      if (!blindedOutputX || !blindedOutputY || !nodeIndex) {
        return null;
      }
      const blindedOutput = secp256k1.ProjectivePoint.fromAffine({
        x: BigInt(`0x${blindedOutputX}`),
        y: BigInt(`0x${blindedOutputY}`),
      });

      return {
        blindedOutput,
        nodeIndex,
      };
    })
    .filter((point): point is BlindedOutputShare => point !== null);

  // evaluate auth priv key using oprf and match with the threshold auth pub key
  const allCombis = kCombinations(
    completedRequests.length,
    EXISTING_USER_AUTHENTICATION_THRESHOLD,
  );
  let seed: Uint8Array | null = null;

  for (const currentCombi of allCombis) {
    const currentCombiPoints = blindedServerPoints.filter((_, index) =>
      currentCombi.includes(index),
    );
    const curvePoints = currentCombiPoints.map((point) => point.blindedOutput);
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
    const derivedPubKey = secp256k1.ProjectivePoint.fromHex(pk);
    const thresholdPubKey =
      secp256k1.ProjectivePoint.fromHex(thresholdAuthPubKey);
    if (derivedPubKey.equals(thresholdPubKey)) {
      seed = recoveredSeed;
      break;
    }
  }

  if (!seed) {
    return Promise.reject(new Error('could not derive encryption key'));
  }

  return Promise.resolve(seed);
};

/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 * @param params.userPasswordHash - The password of the user.
 *
 * @returns - A promise that resolves with the key pair seed successfully.
 */
export const recoverTOPRFSeed = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Record<number, string>;
  verifier: string;
  verifierId: string;
  userPasswordHash: Uint8Array;
}): Promise<Uint8Array> => {
  const {
    authTokens,
    nodeEndpointsMap,
    verifier,
    verifierId,
    userPasswordHash,
  } = params;

  if (authTokens.length < 3) {
    throw new Error('At least 3 auth tokens are required');
  }
  const { a, r } = OPRF.blind(userPasswordHash);

  const promiseArr = authTokens.map(async (authToken) => {
    const endpoint = nodeEndpointsMap[authToken.nodeIndex];
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
    return sendToprfEvalRequest(endpoint, requestParams);
  });

  return Some<ToprfEvalJRPCResponse, Uint8Array>(
    promiseArr,
    async (resultArr) => evaluateSeed(userPasswordHash, r, resultArr),
  );
};
