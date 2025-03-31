import {
  getProxyCoordinatorEndpointIndex,
  toSnakeCaseKeys,
} from '@metamask/auth-network-utils';
import type { INodePub } from '@toruslabs/constants';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';
import type BN from 'bn.js';

import { JRPC_METHODS } from './constants';
import type { NodeAuthTokens } from './interfaces';
import type {
  StoreKeySharesJRPCRequestParams,
  StoreKeySharesJRPCRequest,
  StoreKeySharesJRPCResponse,
} from './jrpcInterfaces';
import { generateShareImportItems, postJRPCRequest } from './utils';

export type CreateStoreKeySharesRequestParamsInput = {
  nodeIndexes: number[];
  nodePubkeys: INodePub[];
  verifier: string;
  verifierId: string;
  authTokens: NodeAuthTokens;
  keyIndex: number;
  oprfKey: BN;
  encryptionPubKey: string;
};

/**
 * Creates the parameters for the store key shares request
 *
 * @param params - The parameters for the store key shares request.
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierId - The verifierId to be used for the store key shares request.
 * @param params.authTokens - The authTokens to be used for the store key shares request.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.encryptionPubKey - The encryption pubkey associated with the oprfKey.
 *
 * @returns The parameters for the store key shares request
 */
export const createStoreKeySharesRequestParams = async (
  params: CreateStoreKeySharesRequestParamsInput,
): Promise<StoreKeySharesJRPCRequestParams> => {
  const {
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierId,
    authTokens,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  } = params;
  const shareImportItems = await generateShareImportItems(
    nodeIndexes,
    nodePubkeys,
    authTokens,
    oprfKey,
    keyIndex,
  );
  return {
    verifier,
    verifierId,
    pubKey: encryptionPubKey,
    shareImportItems,
  };
};

/**
 * Creates a store key shares request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the store key shares request
 * @param params - The parameters for the store key shares request
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
  /**
   * Sends the store key shares request to the given endpoint and returns the store key shares response.
   *
   * @returns The store key shares response.
   */
  const storeKeySharesRequestPromise =
    async (): Promise<StoreKeySharesJRPCResponse> =>
      postJRPCRequest<StoreKeySharesJRPCResponse>(endpoint, authJRPCRequest);
  return storeKeySharesRequestPromise();
};

/**
 * Stores the key shares for the given node endpoints
 *
 * @param nodeEndpoints - The node endpoints to be used for the store key shares request.
 *
 * @param params - The parameters for the store key shares request
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierId - The verifierId to be used for the store key shares request.
 * @param params.authTokens - The authTokens issued by the nodes on authenticating the user.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 *
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.encryptionPubKey - The encryption pubkey associated with the oprfKey.
 *
 * @returns The store key shares request promise.
 */
export const storeKeySharesRequest = async (
  nodeEndpoints: string[],
  params: CreateStoreKeySharesRequestParamsInput,
): Promise<StoreKeySharesJRPCResponse> => {
  const {
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierId,
    authTokens,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  } = params;
  const requestParams = await createStoreKeySharesRequestParams({
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierId,
    authTokens,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  });
  const proxyNodeEndpointIndex = getProxyCoordinatorEndpointIndex(
    nodeEndpoints,
    verifier,
    verifierId,
  );
  const proxyNodeEndpoint = nodeEndpoints[proxyNodeEndpointIndex];

  const storeReqPromise = await createStoreKeySharesRequest(
    proxyNodeEndpoint,
    requestParams,
  );
  return storeReqPromise;
};
