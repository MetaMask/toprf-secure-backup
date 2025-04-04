import { getProxyCoordinatorEndpointIndex, pubKeyToSec1, toSnakeCaseKeys } from "@metamask/auth-network-utils";
import { generateJsonRPCObject } from "@toruslabs/http-helpers";
import { JRPC_METHODS } from "./constants.mjs";
import { generateShareImportItems, postJRPCRequest } from "./utils.mjs";
/**
 * Creates the parameters for the store key shares request
 *
 * @param params - The parameters for the store key shares request.
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
 * @param params.authTokens - The authTokens to be used for the store key shares request.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.authPubKey - The auth pubkey associated with the authentication key pair derived from the seed and input.
 *
 * @returns The parameters for the store key shares request
 */
export const createStoreKeySharesRequestParams = async (params) => {
    const { nodeIndexes, nodePubkeys, authTokens, keyIndex, oprfKey, authPubKey, verifier, verifierId, } = params;
    const shareImportItems = await generateShareImportItems(nodeIndexes, nodePubkeys, authTokens, oprfKey, keyIndex);
    return {
        pubKey: pubKeyToSec1(authPubKey),
        shareImportItems,
        verifier,
        verifierId,
    };
};
/**
 * Creates a store key shares request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the store key shares request
 * @param params - The parameters for the store key shares request
 * @returns The store key shares request promise.
 */
export const createStoreKeySharesRequest = async (endpoint, params) => {
    const authJRPCRequest = generateJsonRPCObject(JRPC_METHODS.STORE_KEY_SHARES_REQUEST, toSnakeCaseKeys(params));
    /**
     * Sends the store key shares request to the given endpoint and returns the store key shares response.
     *
     * @returns The store key shares response.
     */
    const storeKeySharesRequestPromise = async () => postJRPCRequest(endpoint, authJRPCRequest);
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
 * @param params.authPubKey - The  auth pubkey associated with the authentication key pair derived from the seed and input.
 *
 * @returns The store key shares request promise.
 */
export const storeKeyShares = async (nodeEndpoints, params) => {
    const { nodeIndexes, nodePubkeys, authTokens, keyIndex, oprfKey, verifier, verifierId, authPubKey, } = params;
    const requestParams = await createStoreKeySharesRequestParams({
        nodeIndexes,
        nodePubkeys,
        authTokens,
        keyIndex,
        authPubKey,
        oprfKey,
        verifier,
        verifierId,
    });
    const proxyNodeEndpointIndex = getProxyCoordinatorEndpointIndex(nodeEndpoints, verifier, verifierId);
    const proxyNodeEndpoint = nodeEndpoints[proxyNodeEndpointIndex];
    const storeReqPromise = await createStoreKeySharesRequest(proxyNodeEndpoint, requestParams);
    return storeReqPromise;
};
//# sourceMappingURL=storeSharesRequest.mjs.map