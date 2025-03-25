import {
  getProxyCoordinatorEndpointIndex,
  toSnakeCaseKeys,
} from '@metamask/auth-network-utils';
import type { INodePub } from '@toruslabs/constants';
import { generateJsonRPCObject } from '@toruslabs/http-helpers';
import type BN from 'bn.js';

import { JRPC_METHODS } from './constants';
import type {
  StoreKeySharesJRPCRequestParams,
  StoreKeySharesJRPCRequest,
  StoreKeySharesJRPCResponse,
} from './jrpcInterfaces';
import { generateShareImportItems, postJRPCRequest } from './utils';

/**
 * Creates the parameters for the store key shares request
 *
 * @param params - The parameters for the store key shares request.
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierId - The verifierId to be used for the store key shares request.
 * @param params.authToken - The authToken to be used for the store key shares request.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.encryptionPubKey - The encryption pubkey associated with the oprfKey.
 *
 * @returns The parameters for the store key shares request
 */
export const createStoreKeySharesRequestParams = async (params: {
  nodeIndexes: number[];
  nodePubkeys: INodePub[];
  verifier: string;
  verifierId: string;
  authToken: string;
  keyIndex: number;
  oprfKey: BN;
  encryptionPubKey: string;
}): Promise<StoreKeySharesJRPCRequestParams> => {
  const {
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierId,
    authToken,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  } = params;
  const shareImportItems = await generateShareImportItems(
    nodeIndexes,
    nodePubkeys,
    oprfKey,
    keyIndex,
  );
  return {
    verifier,
    verifierId,
    authToken,
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
  const storeKeySharesRequestPromise =
    async (): Promise<StoreKeySharesJRPCResponse> =>
      postJRPCRequest<StoreKeySharesJRPCResponse>(endpoint, authJRPCRequest);
  return storeKeySharesRequestPromise();
};

/**
 * Stores the key shares for the given node endpoints
 *
 * @param params - The parameters for the store key shares request
 * @param params.nodeEndpoints - The node endpoints to be used for the store key shares request.
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierId - The verifierId to be used for the store key shares request.
 * @param params.authToken - The authToken to be used for the store key shares request.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.encryptionPubKey - The encryption pubkey associated with the oprfKey.
 *
 * @returns The store key shares request promise.
 */
export const storeKeySharesRequest = async (params: {
  nodeEndpoints: string[];
  nodeIndexes: number[];
  nodePubkeys: INodePub[];
  verifier: string;
  verifierId: string;
  authToken: string;
  keyIndex: number;
  oprfKey: BN;
  encryptionPubKey: string;
}): Promise<StoreKeySharesJRPCResponse> => {
  const {
    nodeEndpoints,
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierId,
    authToken,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  } = params;
  const requestParams = await createStoreKeySharesRequestParams({
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierId,
    authToken,
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
  const storeReqPromise = createStoreKeySharesRequest(
    proxyNodeEndpoint,
    requestParams,
  );
  return storeReqPromise;
};
