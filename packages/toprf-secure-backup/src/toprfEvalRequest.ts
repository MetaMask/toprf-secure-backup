import {
  Some,
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
import { OPRF, type KeyDeriver } from './oprf';
import {
  checkRateLimitErrors,
  checkAuthTokenErrors,
  mergeEndpointsWithAuthTokens,
  postJRPCRequest,
  getTOPRFError,
  extractRateLimitErrorFromResults,
} from './utils';

type BlindedOutputShare = {
  blindedOutput: ProjPointType<bigint>;
  nodeIndex: number;
  keyShareIndex: number;
};
/**
 * Creates the parameters for the toprf eval request
 *
 * @param authToken - The auth token issued by node to authenticate the request.
 * @param blindedInputX - The blinded input x coordinate to be used for the toprf eval request.
 * @param blindedInputY - The blinded input y coordinate to be used for the toprf eval request.
 * @param authConnectionId - The auth connection name.
 * @param userId - The user id of the user issued by authentication service.
 * @param groupedAuthConnectionId - An optional grouped auth connection name used for authentication with aggregate (single id) verifier.
 * @returns The parameters for the toprf eval jrpc request.
 */
const createToprfEvalRequestParams = (
  authToken: string,
  blindedInputX: string,
  blindedInputY: string,
  authConnectionId: string,
  userId: string,
  groupedAuthConnectionId?: string,
): ToprfEvalJRPCRequestParams => {
  return {
    authToken,
    shareCoefficient: '1', // We apply share coefficient after evaluation so that we can select the share subset after we have responses.
    blindedInputX,
    blindedInputY,
    verifier: groupedAuthConnectionId ?? authConnectionId,
    verifierId: userId,
  };
};

/**
 * Sends a toprf eval request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the toprf eval request
 * @param params - The parameters for the toprf eval request
 * @param client - Optional client identifier sent as the `x-web3-client` header.
 * @returns Array of toprf eval request promises
 */
const sendToprfEvalRequest = async (
  endpoint: string,
  params: ToprfEvalJRPCRequestParams,
  client?: string,
): Promise<ToprfEvalJRPCResponse> => {
  const toprfEvalJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.TOPRF_EVAL_REQUEST,
    params,
  ) as ToprfEvalJRPCRequest;

  return postJRPCRequest<ToprfEvalJRPCResponse>(
    endpoint,
    toprfEvalJRPCRequest,
    client,
  );
};

/**
 * Finds the matching seed from the toprf eval responses
 *
 * @param sortedBlindedOutputs - The sorted blinded outputs from the toprf eval responses.
 * @param userInput - The user input i.e. the password.
 * @param blindingFactor - The random scalar used to blind the input.
 * @param thresholdAuthPubKey - The threshold auth pub key derived from the toprf eval responses.
 * @param keyDeriver - The key deriver to be used for key management and authentication.
 *
 * @returns The seed and key share index if found, otherwise null.
 */
const findMatchingSeedWithAllCombinations = async (
  sortedBlindedOutputs: BlindedOutputShare[],
  userInput: Uint8Array,
  blindingFactor: bigint,
  thresholdAuthPubKey: string,
  keyDeriver?: KeyDeriver,
): Promise<{ seed: Uint8Array; keyShareIndex: number } | null> => {
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

    const recoveredSeed = await OPRF.unblindAndHash(
      userInput,
      blindedOutput,
      blindingFactor,
      keyDeriver,
    );
    const { pk } = deriveAuthenticationKeyPair(recoveredSeed);
    const derivedPubKey = secp256k1.ProjectivePoint.fromHex(pk);
    const thresholdPubKey =
      secp256k1.ProjectivePoint.fromHex(thresholdAuthPubKey);

    if (derivedPubKey.equals(thresholdPubKey)) {
      return {
        seed: recoveredSeed,
        keyShareIndex: currentCombiPoints[0].keyShareIndex,
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
    !('keyShareIndex' in value) || // should have keyShareIndex
    typeof value.keyShareIndex !== 'number' || // `keyShareIndex` should be a number
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
 * @param keyDeriver - The key deriver to be used for the toprf eval request.
 *
 * @returns The toprf eval request result and the key share index
 */
export const validateSeed = async (
  userInput: Uint8Array,
  blindingFactor: bigint,
  resultArr: ToprfEvalJRPCResponse[],
  keyDeriver?: KeyDeriver,
): Promise<{ seed: Uint8Array; keyShareIndex: number }> => {
  // Check for auth token errors before filtering responses
  const authTokenError = checkAuthTokenErrors(resultArr);
  if (authTokenError) {
    throw authTokenError;
  }

  // Check for rate limit errors before filtering responses
  let rateLimitDetails = checkRateLimitErrors(resultArr);
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

      const { blindedOutputX, blindedOutputY, nodeIndex, keyShareIndex } =
        evalResult;

      acc.push({
        blindedOutput: secp256k1.ProjectivePoint.fromAffine({
          x: BigInt(`0x${blindedOutputX}`),
          y: BigInt(`0x${blindedOutputY}`),
        }),
        nodeIndex,
        keyShareIndex,
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

  const seedAndKeyIndex = await findMatchingSeedWithAllCombinations(
    blindedOutputShares,
    userInput,
    blindingFactor,
    thresholdAuthPubKey,
    keyDeriver,
  );
  if (!seedAndKeyIndex) {
    // if seed and key index is not found, check if rate limit error is present in the resultArr
    rateLimitDetails = extractRateLimitErrorFromResults(resultArr);
    if (rateLimitDetails) {
      throw TOPRFError.rateLimitExceeded(rateLimitDetails);
    }
    throw TOPRFError.couldNotDeriveEncryptionKey();
  }

  return seedAndKeyIndex;
};

/**
 * Recovers the seed from the toprf eval responses.
 *
 * @param params - The parameters for the toprf eval request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the toprf eval request.
 * @param params.authConnectionId - The auth connection name used for authentication.
 * @param params.groupedAuthConnectionId - An optional grouped auth connection name used for authentication with aggregate (single id) verifier.
 * @param params.userId - The user id of the user issued by authentication service.
 * @param params.userInput - The user input to be used for the toprf eval request.
 * @param params.keyDeriver - The key deriver to be used for the toprf eval request.
 * @param params.client - Optional client identifier sent as the `x-web3-client` header.
 *
 * @returns - A promise that resolves with the key pair seed and key share index.
 */
export const recoverTOPRFSeed = async (params: {
  authTokens: NodeAuthTokens;
  nodeEndpointsMap: Record<number, string>;
  authConnectionId: string;
  groupedAuthConnectionId?: string;
  userId: string;
  userInput: Uint8Array;
  keyDeriver?: KeyDeriver;
  client?: string;
}): Promise<{ seed: Uint8Array; keyShareIndex: number }> => {
  const {
    authTokens,
    nodeEndpointsMap,
    authConnectionId,
    groupedAuthConnectionId,
    userId,
    userInput,
    keyDeriver,
    client,
  } = params;

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
        authConnectionId,
        userId,
        groupedAuthConnectionId,
      );
      return sendToprfEvalRequest(endpoint, requestParams, client);
    },
  );

  try {
    return await Some<
      ToprfEvalJRPCResponse,
      { seed: Uint8Array; keyShareIndex: number }
    >(promises, async (resultArr) =>
      validateSeed(userInput, r, resultArr, keyDeriver),
    );
  } catch (error) {
    throw getTOPRFError(error as Error);
  }
};
