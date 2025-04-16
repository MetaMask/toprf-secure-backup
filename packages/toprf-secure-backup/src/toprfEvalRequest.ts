import {
  Some,
  SomeError,
  filterCompletedRequests,
  kCombinations,
  lagrangeInterpolationForPoints,
  thresholdSame,
} from '@metamask/auth-network-utils';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1 } from '@noble/curves/secp256k1';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { TOPRF_EVAL_THRESHOLD, JRPC_METHODS } from './constants';
import { TOPRFError } from './errors';
import type { NodeAuthTokens } from './interfaces';
import type {
  ToprfEvalJRPCRequest,
  ToprfEvalJRPCRequestParams,
  ToprfEvalJRPCResponse,
  ToprfEvalResult,
} from './jrpcInterfaces';
import { deriveAuthenticationKeyPair } from './keyDerivation';
import { OPRF } from './oprf';
import {
  checkRateLimitErrors,
  mergeEndpointsWithAuthTokens,
  postJRPCRequest,
} from './utils';

type BlindedOutputShare = {
  blindedOutput: ProjPointType<bigint>;
  nodeIndex: number;
  shareKeyIndex: number;
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
 * Finds the matching seed from the toprf eval responses
 *
 * @param sortedBlindedOutputs - The sorted blinded outputs from the toprf eval responses.
 * @param userInput - The user input i.e. the password.
 * @param blindingFactor - The random scalar used to blind the input.
 * @param thresholdAuthPubKey - The threshold auth pub key derived from the toprf eval responses.
 *
 * @returns The seed and share key index if found, otherwise null.
 */
const findMatchingSeedWithAllCombinations = (
  sortedBlindedOutputs: BlindedOutputShare[],
  userInput: Uint8Array,
  blindingFactor: bigint,
  thresholdAuthPubKey: string,
): { seed: Uint8Array; shareKeyIndex: number } | null => {
  const allCombis = kCombinations(
    sortedBlindedOutputs.length,
    TOPRF_EVAL_THRESHOLD,
  );

  for (const currentCombi of allCombis) {
    const currentCombiPoints = sortedBlindedOutputs.filter((_, index) =>
      currentCombi.includes(index),
    );
    const selectedBlindedOutputs = currentCombiPoints.map(
      (point) => point.blindedOutput,
    );
    const nodeIndexes = currentCombiPoints.map((point) =>
      BigInt(point.nodeIndex),
    );

    const blindedOutput = lagrangeInterpolationForPoints(
      secp256k1.CURVE.n,
      selectedBlindedOutputs,
      nodeIndexes,
    );

    const recoveredSeed = OPRF.unblindAndHash(
      userInput,
      blindedOutput,
      blindingFactor,
    );
    const { pk } = deriveAuthenticationKeyPair(recoveredSeed);
    const derivedPubKey = secp256k1.ProjectivePoint.fromHex(pk);
    const thresholdPubKey =
      secp256k1.ProjectivePoint.fromHex(thresholdAuthPubKey);

    if (derivedPubKey.equals(thresholdPubKey)) {
      return {
        seed: recoveredSeed,
        shareKeyIndex: currentCombiPoints[0].shareKeyIndex,
      };
    }
  }

  return null;
};

/**
 * Asserts that the value given is a valid toprf eval result
 *
 * @param value - The value to be asserted
 * @returns True if the value is a valid toprf eval result, otherwise false
 */
const assertIsValidToprfEvalResult = (
  value: unknown,
): value is ToprfEvalResult => {
  if (
    typeof value !== 'object' || // `value` should be an object
    value === null || // `value` should not be null
    !('blindedOutputX' in value) || // `value` should have `blindedOutputX`
    typeof value.blindedOutputX !== 'string' || // `blindedOutputX` should be a string
    !('blindedOutputY' in value) || // `value` should have `blindedOutputY`
    typeof value.blindedOutputY !== 'string' || // `blindedOutputY` should be a string
    !('nodeIndex' in value) || // `value` should have `nodeIndex`
    typeof value.nodeIndex !== 'number' || // `nodeIndex` should be a number
    !('shareKeyIndex' in value) || // should have shareKeyIndex
    typeof value.shareKeyIndex !== 'number' || // `shareKeyIndex` should be a number
    !('pubKey' in value) || // should have pubKey
    typeof value.pubKey !== 'string' // `pubKey` should be a string
  ) {
    return false;
  }
  return true;
};

/**
 * Validates the seed from the toprf eval responses
 *
 * @param userInput - The user input i.e. the password.
 * @param blindingFactor - The random scalar used to blind the input.
 * @param resultArr - The toprf eval request result
 * @returns The toprf eval request result and the share key index
 */
export const validateSeed = async (
  userInput: Uint8Array,
  blindingFactor: bigint,
  resultArr: ToprfEvalJRPCResponse[],
): Promise<{ seed: Uint8Array; shareKeyIndex: number }> => {
  // Check for rate limit errors before filtering responses
  const rateLimitDetails = checkRateLimitErrors(resultArr);
  if (rateLimitDetails) {
    throw TOPRFError.rateLimitExceeded(rateLimitDetails);
  }

  const completedRequests =
    filterCompletedRequests<ToprfEvalJRPCResponse>(resultArr);

  if (completedRequests.length < TOPRF_EVAL_THRESHOLD) {
    throw TOPRFError.insufficientValidResponses(
      `Insufficient toprf eval request results, expected ${TOPRF_EVAL_THRESHOLD} but got ${completedRequests.length}`,
    );
  }
  const thresholdAuthPubKey = thresholdSame(
    completedRequests.map((res) => res.result?.pubKey),
    TOPRF_EVAL_THRESHOLD,
  );

  if (!thresholdAuthPubKey) {
    throw TOPRFError.couldNotDeriveThresholdAuthPubKey();
  }

  const blindedOutputShares = completedRequests.reduce<BlindedOutputShare[]>(
    (acc, resp) => {
      const evalResult = resp.result;
      if (!assertIsValidToprfEvalResult(evalResult)) {
        return acc;
      }

      const { blindedOutputX, blindedOutputY, nodeIndex, shareKeyIndex } =
        evalResult;

      acc.push({
        blindedOutput: secp256k1.ProjectivePoint.fromAffine({
          x: BigInt(`0x${blindedOutputX}`),
          y: BigInt(`0x${blindedOutputY}`),
        }),
        nodeIndex,
        shareKeyIndex,
      });

      return acc;
    },
    [],
  );

  if (blindedOutputShares.length < TOPRF_EVAL_THRESHOLD) {
    throw TOPRFError.insufficientValidResponses(
      `Insufficient valid blinded outputs, expected: ${TOPRF_EVAL_THRESHOLD}, received: ${blindedOutputShares.length}`,
    );
  }

  const seedAndKeyIndex = findMatchingSeedWithAllCombinations(
    blindedOutputShares,
    userInput,
    blindingFactor,
    thresholdAuthPubKey,
  );
  if (!seedAndKeyIndex) {
    throw TOPRFError.couldNotDeriveEncryptionKey();
  }

  return seedAndKeyIndex;
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
 * @returns - A promise that resolves with the key pair seed and share key index.
 */
export const recoverTOPRFSeed = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Record<number, string>;
  verifier: string;
  verifierId: string;
  userInput: Uint8Array;
}): Promise<{ seed: Uint8Array; shareKeyIndex: number }> => {
  const { authTokens, nodeEndpointsMap, verifier, verifierId, userInput } =
    params;

  if (authTokens.length < TOPRF_EVAL_THRESHOLD) {
    throw TOPRFError.insufficientAuthTokens(
      `At least ${TOPRF_EVAL_THRESHOLD} auth tokens are required.`,
    );
  }
  const { a, r } = OPRF.blind(userInput);

  const endpointsWithAuthTokens = mergeEndpointsWithAuthTokens(
    authTokens,
    nodeEndpointsMap,
  );

  const promises = endpointsWithAuthTokens.map(
    async ({ endpoint, authToken }) => {
      const requestParams = createToprfEvalRequestParams(
        authToken.authToken,
        a.x.toString(16),
        a.y.toString(16),
        verifier,
        verifierId,
      );
      return sendToprfEvalRequest(endpoint, requestParams);
    },
  );

  try {
    return await Some<
      ToprfEvalJRPCResponse,
      { seed: Uint8Array; shareKeyIndex: number }
    >(promises, async (resultArr) => validateSeed(userInput, r, resultArr));
  } catch (error) {
    if (
      error instanceof SomeError &&
      error.predicate &&
      error.predicate instanceof TOPRFError
    ) {
      throw error.predicate;
    }

    throw error;
  }
};
