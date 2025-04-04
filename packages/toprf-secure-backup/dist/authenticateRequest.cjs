"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateUser = exports.validateThresholdAuthenticateResponses = void 0;
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
 * @returns The parameters for the authenticate JRPC request.
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
/**
 * Sends an authenticate request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @returns The authenticate request promise.
 */
const sendAuthenticateRequest = async (endpoint, params) => {
    const authJRPCRequest = (0, http_helpers_1.generateJsonRPCObject)(constants_1.JRPC_METHODS.AUTHENTICATE_REQUEST, params);
    return (0, utils_1.postJRPCRequest)(endpoint, authJRPCRequest);
};
/**
 * Validates the authenticate responses
 *
 * @param resultArr - The authenticate request result
 * @returns The authenticate request result
 */
const validateThresholdAuthenticateResponses = async (resultArr) => {
    const completedRequests = resultArr.filter((res) => {
        if (!res || typeof res !== 'object') {
            return false;
        }
        if ('error' in res && res.error) {
            return false;
        }
        return true;
    });
    if (completedRequests.length < constants_1.EXISTING_USER_AUTHENTICATION_THRESHOLD) {
        throw auth_network_utils_1.TOPRFError.invalidAuthenticateResults(`Not enough completed requests. Expected: ${constants_1.EXISTING_USER_AUTHENTICATION_THRESHOLD}, got: ${completedRequests.length}`);
    }
    const pubData = completedRequests.map((res) => {
        const result = res.result;
        return {
            pubKey: result.pubKey,
            keyIndex: result.keyIndex,
        };
    });
    const thresholdPubData = (0, auth_network_utils_1.thresholdSame)(pubData, constants_1.EXISTING_USER_AUTHENTICATION_THRESHOLD);
    if (!thresholdPubData) {
        throw auth_network_utils_1.TOPRFError.invalidAuthenticateResults(`Threshold pubKey not found for ${JSON.stringify(pubData)}`);
    }
    const newUser = !thresholdPubData.pubKey;
    const hasMaxResponses = completedRequests.length >= constants_1.NEW_USER_AUTHENTICATION_THRESHOLD;
    // if it is new user then we need to wait for all the responses because we will need all nodes to be online
    // while storing shares of this new user.
    if (newUser && !hasMaxResponses) {
        throw auth_network_utils_1.TOPRFError.invalidAuthenticateResults(`Not enough completed requests. Expected: ${constants_1.NEW_USER_AUTHENTICATION_THRESHOLD}, got: ${completedRequests.length}`);
    }
    return completedRequests.map((res) => res.result);
};
exports.validateThresholdAuthenticateResponses = validateThresholdAuthenticateResponses;
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
    const requestParams = createAuthenticateRequestParams(idToken, verifier, verifierID, commitmentSignatures);
    // start with half the nodes count optimistically.
    const promiseArr = endpoints.map(async (endpoint) => sendAuthenticateRequest(endpoint, requestParams));
    const results = await (0, auth_network_utils_1.Some)(promiseArr, async (responses) => (0, exports.validateThresholdAuthenticateResponses)(responses));
    if (!results || results.length === 0) {
        throw new Error('Invalid authenticate request results');
    }
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