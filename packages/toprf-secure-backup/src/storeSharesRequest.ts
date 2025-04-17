import {
  getProxyCoordinatorNodeIndex,
  isJSONRPCError,
  toSnakeCaseKeys,
  uint8ArrayToHex,
} from '@metamask/auth-network-utils';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';

import { JRPC_METHODS } from './constants';
import type { NodeAuthTokens } from './interfaces';
import type {
  StoreKeySharesJRPCRequestParams,
  StoreKeySharesJRPCResponse,
  StoreKeySharesJRPCRequest,
} from './jrpcInterfaces';
import {
  generateShareImportItems,
  parseJsonRpcError,
  postJRPCRequest,
} from './utils';

export type CreateStoreKeySharesRequestParamsInput = {
  nodeEndpointsMap: Record<number, string>;
  authTokens: NodeAuthTokens;
  shareKeyIndex: number;
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
 * @param params.shareKeyIndex - The share key index to be used for the store key shares request.
 * It should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
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
    shareKeyIndex,
    oprfKey,
    authPubKey,
    verifier,
    verifierId,
  } = params;
  const shareImportItems = await generateShareImportItems(
    nodeEndpointsMap,
    authTokens,
    oprfKey,
    shareKeyIndex,
  );
  return {
    pubKey: uint8ArrayToHex(authPubKey),
    shareImportItems,
    verifier,
    verifierId,
  };
};

/**
 * Sends a store key shares request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the store key shares request.
 * @param params - The parameters for the store key shares request.
 *
 * @returns The store key shares request promise.
 */
export const sendStoreKeySharesRequest = async (
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
 * @param params.shareKeyIndex - The share key index to be used for the store key shares request.
 * It should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
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
    shareKeyIndex,
    oprfKey,
    verifier,
    verifierId,
    authPubKey,
  } = params;
  const requestParams = await createStoreKeySharesRequestParams({
    nodeEndpointsMap,
    authTokens,
    shareKeyIndex,
    authPubKey,
    oprfKey,
    verifier,
    verifierId,
  });
  const proxyNodeEndpointIndex = getProxyCoordinatorNodeIndex(
    authTokens.map((token) => token.nodeIndex),
    verifier,
    verifierId,
  );
  const proxyNodeEndpoint = nodeEndpointsMap[proxyNodeEndpointIndex];
  const storeKeyShareResponse = await sendStoreKeySharesRequest(
    proxyNodeEndpoint,
    requestParams,
  );

  if (isJSONRPCError(storeKeyShareResponse.error)) {
    const error = parseJsonRpcError(storeKeyShareResponse.error);
    throw error;
  }

  return storeKeyShareResponse;
};

export type CreateKeyChangeRequestParamsInput = {
  nodeEndpointsMap: Record<number, string>;
  authTokens: NodeAuthTokens;
  shareKeyIndex: number;
  verifier: string;
  verifierId: string;
  newOprfKey: bigint;
  newAuthPubKey: Uint8Array;
  oldAuthPrivKey: bigint;
};

export type KeyChangeRequestParams = CreateKeyChangeRequestParamsInput;

/**
 * Creates the parameters for the key change request
 *
 * @param params - The parameters for the key change request.
 * @param params.nodeEndpointsMap - The map of node indexes to endpoints.
 * @param params.authTokens - The authTokens to be used for the key change request.
 * @param params.shareKeyIndex - The share key index to be used for the key change request.
 * @param params.newOprfKey - The new oprfKey to be used for the key change request.
 * @param params.newAuthPubKey - The new auth pubkey for the updated authentication.
 * @param params.oldAuthPrivKey - The old auth private key used to sign the key change request.
 *
 * @returns The parameters for the key change request
 */
export const createKeyChangeRequestParams = async (
  params: CreateKeyChangeRequestParamsInput,
): Promise<StoreKeySharesJRPCRequestParams> => {
  const {
    nodeEndpointsMap,
    authTokens,
    shareKeyIndex,
    newOprfKey,
    newAuthPubKey,
    oldAuthPrivKey,
    verifier,
    verifierId,
  } = params;

  // Generate share import items with the old auth private key for signing
  const shareImportItems = await generateShareImportItems<'keyChange'>(
    nodeEndpointsMap,
    authTokens,
    newOprfKey,
    shareKeyIndex,
    oldAuthPrivKey,
  );

  return {
    pubKey: uint8ArrayToHex(newAuthPubKey),
    shareImportItems,
    verifier,
    verifierId,
  };
};

/**
 * Changes the key shares for the given node endpoints
 *
 * @param params - The parameters for the key change request
 * @param params.nodeEndpointsMap - The node endpoints map to be used for the key change request.
 * @param params.verifier - The verifier to be used for the key change request.
 * @param params.verifierId - The verifierId to be used for the key change request.
 * @param params.authTokens - The authTokens issued by the nodes on authenticating the user.
 * @param params.shareKeyIndex - The share key index to be used for the key change request.
 * @param params.newOprfKey - The new oprfKey to be used for the key change request.
 * @param params.newAuthPubKey - The new auth pubkey for the updated authentication.
 * @param params.oldAuthPrivKey - The old auth private key used to sign the key change request.
 *
 * @returns The key change request promise.
 */
export const changeKeyShares = async (
  params: KeyChangeRequestParams,
): Promise<StoreKeySharesJRPCResponse> => {
  const {
    nodeEndpointsMap,
    authTokens,
    shareKeyIndex,
    newOprfKey,
    newAuthPubKey,
    oldAuthPrivKey,
    verifier,
    verifierId,
  } = params;

  const requestParams = await createKeyChangeRequestParams({
    nodeEndpointsMap,
    authTokens,
    shareKeyIndex,
    newOprfKey,
    newAuthPubKey,
    oldAuthPrivKey,
    verifier,
    verifierId,
  });

  const proxyNodeEndpointIndex = getProxyCoordinatorNodeIndex(
    authTokens.map((token) => token.nodeIndex),
    verifier,
    verifierId,
  );
  const proxyNodeEndpoint = nodeEndpointsMap[proxyNodeEndpointIndex];

  // Use the same JRPC method as store shares but with the key change parameters
  const keyChangeResponse = await sendStoreKeySharesRequest(
    proxyNodeEndpoint,
    requestParams,
  );

  if (isJSONRPCError(keyChangeResponse.error)) {
    const error = parseJsonRpcError(keyChangeResponse.error);
    throw error;
  }

  return keyChangeResponse;
};
