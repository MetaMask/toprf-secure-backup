import { getProxyCoordinatorEndpointIndex } from '@metamask/auth-network-utils';
import type { INodePub } from '@toruslabs/constants';
import { generateJsonRPCObject, post } from '@toruslabs/http-helpers';
import type BN from 'bn.js';

import { JRPC_METHODS } from './constants';
import type {
  StoreKeySharesJRPCRequestParams,
  StoreKeySharesJRPCRequest,
} from './jrpcInterfaces';
import { generateShareImportItems } from './utils';

/**
 * Creates the parameters for the store key shares request
 *
 * @param params - The parameters for the store key shares request.
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierID - The verifierID to be used for the store key shares request.
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
  verifierID: string;
  authToken: string;
  keyIndex: number;
  oprfKey: BN;
  encryptionPubKey: string;
}): Promise<StoreKeySharesJRPCRequestParams> => {
  const {
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierID,
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
    verifier_id: verifierID,
    auth_token: authToken,
    pub_key: encryptionPubKey,
    share_import_items: shareImportItems,
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
): Promise<void> => {
  const authJRPCRequest = generateJsonRPCObject(
    JRPC_METHODS.STORE_KEY_SHARES_REQUEST,
    params,
  ) as StoreKeySharesJRPCRequest;
  const p = async () =>
    post<void>(endpoint, authJRPCRequest, {}, { logTracingHeader: false });
  return p();
};

/**
 * Stores the key shares for the given node endpoints
 *
 * @param params - The parameters for the store key shares request
 * @param params.nodeEndpoints - The node endpoints to be used for the store key shares request.
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierID - The verifierID to be used for the store key shares request.
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
  verifierID: string;
  authToken: string;
  keyIndex: number;
  oprfKey: BN;
  encryptionPubKey: string;
}): Promise<void> => {
  const {
    nodeEndpoints,
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierID,
    authToken,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  } = params;
  const requestParams = await createStoreKeySharesRequestParams({
    nodeIndexes,
    nodePubkeys,
    verifier,
    verifierID,
    authToken,
    keyIndex,
    oprfKey,
    encryptionPubKey,
  });
  const proxyNodeEndpointIndex = getProxyCoordinatorEndpointIndex(
    nodeEndpoints,
    verifier,
    verifierID,
  );
  const proxyNodeEndpoint = nodeEndpoints[proxyNodeEndpointIndex];
  const storeReqPromise = createStoreKeySharesRequest(
    proxyNodeEndpoint,
    requestParams,
  );
  return storeReqPromise;
};
