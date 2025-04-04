"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateUser = exports.createAuthenticateRequest = exports.createAuthenticateRequestParams = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const http_helpers_1 = require("@toruslabs/http-helpers");
const constants_1 = require("./constants.cjs");
const utils_1 = require("./utils.cjs");
/**
 * Creates the parameters for the authenticate request
 *
 * @param idToken - The idToken to be used for the authenticate request
 * @param verifier - The verifier to be used for the authenticate request
 * @param verifierID - The verifierID to be used for the authenticate request
 * @param commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 *
 * @returns The parameters for the authenticate jrpc request.
 */
const createAuthenticateRequestParams = (idToken, verifier, verifierID, commitmentSignatures) => {
    return {
        authData: {
            authenticationContext: {
                idToken,
                verifier,
                verifierId: verifierID,
            },
        },
        commitmentSignatures,
        clientTime: Math.floor(Date.now() / 1000).toString(),
    };
};
exports.createAuthenticateRequestParams = createAuthenticateRequestParams;
/**
 * Creates a authenticate request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @returns The authenticate request promise.
 */
const createAuthenticateRequest = async (endpoint, params) => {
    const authJRPCRequest = (0, http_helpers_1.generateJsonRPCObject)(constants_1.JRPC_METHODS.AUTHENTICATE_REQUEST, params);
    /**
     * Sends the authenticate request to the given endpoint and returns the authenticate response.
     *
     * @returns The authenticate response.
     */
    const authRequestPromise = async () => (0, utils_1.postJRPCRequest)(endpoint, authJRPCRequest);
    return authRequestPromise();
};
exports.createAuthenticateRequest = createAuthenticateRequest;
/**
 * Validates the authenticate responses
 *
 * @param resultArr - The authenticate request result
 * @param nodesCount - The number of nodes.
 * @returns The authenticate request result
 */
const validateThresholdAuthenticateResponses = async (resultArr, nodesCount) => {
    // start with half the nodes count optimistically.
    const threshold = Math.floor(nodesCount / 2) + 1;
    const completedRequests = resultArr.filter((res) => {
        if (!res || typeof res !== 'object') {
            return false;
        }
        if ('error' in res && res.error) {
            return false;
        }
        return true;
    });
    if (completedRequests.length >= threshold) {
        const pubData = completedRequests.map((res) => {
            const result = res.result;
            return {
                pubKey: result.pubKey,
                keyIndex: result.keyIndex,
            };
        });
        const thresholdPubData = (0, auth_network_utils_1.thresholdSame)(pubData, threshold);
        const isExistingUser = Boolean(thresholdPubData?.pubKey);
        const hasThresholdResponses = threshold < nodesCount;
        const hasMaxResponses = nodesCount === completedRequests.length;
        // if it is old user thn we can return the result, as soon as we get the threshold number of responses.
        // if it is new user then we need to wait for all the responses because we will need all nodes to be online
        // while storing shares of this new user.
        if (isExistingUser && hasThresholdResponses) {
            return Promise.resolve(completedRequests.map((res) => res.result));
        }
        else if (!isExistingUser && hasMaxResponses) {
            return Promise.resolve(completedRequests.map((res) => res.result));
        }
    }
    return Promise.reject(new Error(`invalid authenticate results ${JSON.stringify(resultArr)}`));
};
/**
 * Authenticates the user with the given idToken and verifierID and validates the responses.
 *
 * @param params - The parameters for the authenticate request
 * @param params.idToken - The idToken to be used for the authenticate request
 * @param params.verifier - The verifier to be used for the authenticate request
 * @param params.verifierID - The verifierID to be used for the authenticate request
 * @param params.sessionPrivateKey - The session private key used for commitment request.
 * @param params.endpoints - The endpoints to be used for the authenticate request
 * @param params.commitmentSignatures - The idToken commitment signatures to be used for the authenticate request.
 * @returns resultArr - The authenticate request result, where each element is
 * a signed authenticate data from a node.
 */
const authenticateUser = async (params) => {
    const { idToken, endpoints, verifier, verifierID, commitmentSignatures, sessionPrivateKey, } = params;
    const requestParams = (0, exports.createAuthenticateRequestParams)(idToken, verifier, verifierID, commitmentSignatures);
    const promiseArr = endpoints.map(async (endpoint) => (0, exports.createAuthenticateRequest)(endpoint, requestParams));
    const results = await new Promise((resolve, reject) => {
        (0, auth_network_utils_1.Some)(promiseArr, async (resultArr) => validateThresholdAuthenticateResponses(resultArr, endpoints.length))
            .then((resultArr) => {
            if (!resultArr || resultArr.length === 0) {
                throw new Error('Invalid authenticate request results');
            }
            else {
                return resolve(resultArr);
            }
        })
            .catch(reject);
    });
    const decryptedAuthResults = await Promise.all(results.map(async (result) => {
        const { authToken, nodeIndex, nodePubKey, pubKey, keyIndex } = result;
        const decryptedAuthToken = await (0, utils_1.decryptAuthToken)(authToken, sessionPrivateKey);
        return {
            authToken: decryptedAuthToken,
            nodeIndex,
            nodePubKey,
            pubKey,
            keyIndex,
        };
    }));
    return decryptedAuthResults;
};
exports.authenticateUser = authenticateUser;
//# sourceMappingURL=authenticateRequest.cjs.map