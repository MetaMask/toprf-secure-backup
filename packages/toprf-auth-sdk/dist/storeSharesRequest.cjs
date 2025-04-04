"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.storeKeyShares = exports.createStoreKeySharesRequest = exports.createStoreKeySharesRequestParams = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const http_helpers_1 = require("@toruslabs/http-helpers");
const constants_1 = require("./constants.cjs");
const utils_1 = require("./utils.cjs");
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
const createStoreKeySharesRequestParams = async (params) => {
    const { nodeIndexes, nodePubkeys, authTokens, keyIndex, oprfKey, authPubKey, verifier, verifierId, } = params;
    const shareImportItems = await (0, utils_1.generateShareImportItems)(nodeIndexes, nodePubkeys, authTokens, oprfKey, keyIndex);
    return {
        pubKey: (0, auth_network_utils_1.pubKeyToSec1)(authPubKey),
        shareImportItems,
        verifier,
        verifierId,
    };
};
exports.createStoreKeySharesRequestParams = createStoreKeySharesRequestParams;
/**
 * Creates a store key shares request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the store key shares request
 * @param params - The parameters for the store key shares request
 * @returns The store key shares request promise.
 */
const createStoreKeySharesRequest = async (endpoint, params) => {
    const authJRPCRequest = (0, http_helpers_1.generateJsonRPCObject)(constants_1.JRPC_METHODS.STORE_KEY_SHARES_REQUEST, (0, auth_network_utils_1.toSnakeCaseKeys)(params));
    /**
     * Sends the store key shares request to the given endpoint and returns the store key shares response.
     *
     * @returns The store key shares response.
     */
    const storeKeySharesRequestPromise = async () => (0, utils_1.postJRPCRequest)(endpoint, authJRPCRequest);
    return storeKeySharesRequestPromise();
};
exports.createStoreKeySharesRequest = createStoreKeySharesRequest;
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
const storeKeyShares = async (nodeEndpoints, params) => {
    const { nodeIndexes, nodePubkeys, authTokens, keyIndex, oprfKey, verifier, verifierId, authPubKey, } = params;
    const requestParams = await (0, exports.createStoreKeySharesRequestParams)({
        nodeIndexes,
        nodePubkeys,
        authTokens,
        keyIndex,
        authPubKey,
        oprfKey,
        verifier,
        verifierId,
    });
    const proxyNodeEndpointIndex = (0, auth_network_utils_1.getProxyCoordinatorEndpointIndex)(nodeEndpoints, verifier, verifierId);
    const proxyNodeEndpoint = nodeEndpoints[proxyNodeEndpointIndex];
    const storeReqPromise = await (0, exports.createStoreKeySharesRequest)(proxyNodeEndpoint, requestParams);
    return storeReqPromise;
};
exports.storeKeyShares = storeKeyShares;
//# sourceMappingURL=storeSharesRequest.cjs.map