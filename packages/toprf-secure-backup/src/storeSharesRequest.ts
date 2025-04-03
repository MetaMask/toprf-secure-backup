import {
  getProxyCoordinatorEndpointIndex,
  pubKeyToSec1,
  toSnakeCaseKeys,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type { NodeAuthTokens } from './interfaces';
import type {
  StoreKeySharesJRPCRequestParams,
  StoreKeySharesJRPCRequest,
  StoreKeySharesJRPCResponse,
} from './jrpcInterfaces';
import { generateShareImportItems, postJRPCRequest } from './utils';

export type CreateStoreKeySharesRequestParamsInput = {
  nodeEndpointsMap: Record<number, string>;
  authTokens: NodeAuthTokens;
  keyIndex: number;
  verifier: string;
  verifierId: string;
  oprfKey: bigint;
  authPubKey: Uint8Array;
};

export type StoreKeySharesRequestParams =
  CreateStoreKeySharesRequestParamsInput;
/**
 * Creates the parameters for the store key shares request
 *
 * @param params - The parameters for the store key shares request.
 * @param params.nodeEndpointsMap - The map of node indexes to endpoints.
 * @param params.authTokens - The authTokens to be used for the store key shares request.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.authPubKey - The auth pubkey associated with the authentication key pair derived from the seed and input.
 *
 * @returns The parameters for the store key shares request
 */
export const createStoreKeySharesRequestParams = async (
  params: CreateStoreKeySharesRequestParamsInput,
): Promise<StoreKeySharesJRPCRequestParams> => {
  const {
    nodeEndpointsMap,
    authTokens,
    keyIndex,
    oprfKey,
    authPubKey,
    verifier,
    verifierId,
  } = params;
  const shareImportItems = await generateShareImportItems(
    nodeEndpointsMap,
    authTokens,
    oprfKey,
    keyIndex,
  );
  return {
    pubKey: pubKeyToSec1(authPubKey),
    shareImportItems,
    verifier,
    verifierId,
  };
};

/**
 * Creates a store key shares request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the store key shares request.
 * @param params - The parameters for the store key shares request.
 *
 * @returns The store key shares request promise.
 */
export const createStoreKeySharesRequest = async (
  endpoint: string,
  params: StoreKeySharesJRPCRequestParams,
): Promise<StoreKeySharesJRPCResponse> => {
  const authJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.STORE_KEY_SHARES_REQUEST,
    toSnakeCaseKeys(params),
  ) as StoreKeySharesJRPCRequest;

  return postJRPCRequest<StoreKeySharesJRPCResponse>(endpoint, authJRPCRequest);
};

/**
 * Stores the key shares for the given node endpoints
 *
 * @param params - The parameters for the store key shares request
 * @param params.nodeEndpointsMap - The node endpoints map to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierId - The verifierId to be used for the store key shares request.
 * @param params.authTokens - The authTokens issued by the nodes on authenticating the user.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 *
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.authPubKey - The  auth pubkey associated with the authentication key pair derived from the seed and input.
 *
 * @returns The store key shares request promise.
 */
export const storeKeyShares = async (
  params: StoreKeySharesRequestParams,
): Promise<StoreKeySharesJRPCResponse> => {
  const {
    nodeEndpointsMap,
    authTokens,
    keyIndex,
    oprfKey,
    verifier,
    verifierId,
    authPubKey,
  } = params;
  const requestParams = await createStoreKeySharesRequestParams({
    nodeEndpointsMap,
    authTokens,
    keyIndex,
    authPubKey,
    oprfKey,
    verifier,
    verifierId,
  });
  const proxyNodeEndpointIndex = getProxyCoordinatorEndpointIndex(
    Object.values(nodeEndpointsMap),
    verifier,
    verifierId,
  );
  const proxyNodeEndpoint = nodeEndpointsMap[proxyNodeEndpointIndex];

  const storeReqPromise = await createStoreKeySharesRequest(
    proxyNodeEndpoint,
    requestParams,
  );
  return storeReqPromise;
};
