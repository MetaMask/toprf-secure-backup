import {
  Some,
  TOPRFError,
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
const createToprfEvalRequestParams = (
  authToken: string,
  blindedInputX: string,
  blindedInputY: string,
  verifier: string,
  verifierId: string,
): ToprfEvalJRPCRequestParams => {
  return {
    authToken,
    shareCoefficient: '1', // We apply share coefficient after evaluation so that we can select the share subset after we have responses.
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
 * Validates the seed from the toprf eval responses
 *
 * @param userInput - The user input i.e. the password.
 * @param randomScalar - The random scalar used to blind the input.
 * @param resultArr - The toprf eval request result
 * @returns The toprf eval request result
 */
export const validateSeed = async (
  userInput: Uint8Array,
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
    throw TOPRFError.insufficientValidResponses(
      `Insufficient toprf eval request results, expected ${EXISTING_USER_AUTHENTICATION_THRESHOLD} but got ${completedRequests.length}`,
    );
  }
  const thresholdAuthPubKey = thresholdSame(
    completedRequests.map((res) => res.result?.pubKey),
    EXISTING_USER_AUTHENTICATION_THRESHOLD,
  );

  if (!thresholdAuthPubKey) {
    throw TOPRFError.couldNotDeriveThresholdAuthPubKey();
  }

  const blindedOutputs = completedRequests
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
    const currentCombiPoints = blindedOutputs.filter((_, index) =>
      currentCombi.includes(index),
    );
    const selectedBlindedOutputs = currentCombiPoints.map(
      (point) => point.blindedOutput,
    );
    const nodeIndexes = currentCombiPoints.map((point) =>
      BigInt(point.nodeIndex),
    );
    // Interpolate the curve points directly using Lagrange interpolation
    const blindedOutput = lagrangeInterpolationForPoints(
      secp256k1.CURVE.n,
      selectedBlindedOutputs,
      nodeIndexes,
    );

    // Unblind and hash the result
    const recoveredSeed = OPRF.unblindAndHash(
      userInput,
      blindedOutput,
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
    throw TOPRFError.couldNotDeriveEncryptionKey();
  }

  return Promise.resolve(seed);
};

/**
 * Recovers the seed from the toprf eval responses.
 *
 * @param params - The parameters for the toprf eval request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the toprf eval request.
 * @param params.userInput - The user input i.e. the password.
 *
 * @returns - A promise that resolves with the key pair seed successfully.
 */
export const recoverTOPRFSeed = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Map<number, string>;
  verifier: string;
  verifierId: string;
  userInput: Uint8Array;
}): Promise<Uint8Array> => {
  const { authTokens, nodeEndpointsMap, verifier, verifierId, userInput } =
    params;

  if (authTokens.length < 3) {
    throw new Error('At least 3 auth tokens are required');
  }
  const { a, r } = OPRF.blind(userInput);

  const promises: Promise<ToprfEvalJRPCResponse>[] = [];
  for (const authToken of authTokens) {
    const endpoint = nodeEndpointsMap.get(authToken.nodeIndex);
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
    promises.push(sendToprfEvalRequest(endpoint, requestParams));
  }

  return Some<ToprfEvalJRPCResponse, Uint8Array>(promises, async (resultArr) =>
    validateSeed(userInput, r, resultArr),
  );
};
