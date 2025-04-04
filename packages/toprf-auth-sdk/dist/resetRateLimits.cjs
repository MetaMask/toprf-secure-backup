"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetRateLimits = exports.validateThresholdResetRateLimitResponses = exports.createResetRateLimitRequest = exports.createResetRateLimitRequestParams = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const http_helpers_1 = require("@toruslabs/http-helpers");
const constants_1 = require("./constants.cjs");
const utils_1 = require("./utils.cjs");
/**
 * Creates the parameters for the reset rate limit request
 *
 * @param authToken - The auth token issued by node to authenticate the request.
 * @param signature - The signature of the signedData using user's authentication key.
 * @param signedData - The data that is signed for to validate if user has access to authentication key.
 * @param verifier - The verifier name.
 * @param verifierId - The verifier id of the user.
 *
 * @returns The parameters for the reset rate limit jrpc request.
 */
const createResetRateLimitRequestParams = (authToken, signature, signedData, verifier, verifierId) => {
    return {
        authToken,
        signature,
        signedData,
        verifier,
        verifierId,
    };
};
exports.createResetRateLimitRequestParams = createResetRateLimitRequestParams;
/**
 * Creates a reset rate limit request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the reset rate limit request
 * @param params - The parameters for the reset rate limit request
 * @returns Array of reset rate limit request promises
 */
const createResetRateLimitRequest = async (endpoint, params) => {
    const resetRateLimitJRPCRequest = (0, http_helpers_1.generateJsonRPCObject)(constants_1.JRPC_METHODS.RESET_RATE_LIMIT_REQUEST, params);
    /**
     * Sends the reset rate limit request to the given endpoint and returns the reset rate limit response.
     *
     * @returns The reset rate limit response.
     */
    const resetRateLimitResponse = (0, utils_1.postJRPCRequest)(endpoint, resetRateLimitJRPCRequest);
    return resetRateLimitResponse;
};
exports.createResetRateLimitRequest = createResetRateLimitRequest;
/**
 * Validates the reset rate limit responses
 *
 * @param resultArr - The reset rate limit request result
 * @param threshold - The threshold for the number reset rate limit responses to be valid
 * @returns The reset rate limit request result
 */
const validateThresholdResetRateLimitResponses = async (resultArr, threshold) => {
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
        return Promise.resolve(true);
    }
    return Promise.reject(new Error(`invalid reset rate limit results ${JSON.stringify(resultArr)}`));
};
exports.validateThresholdResetRateLimitResponses = validateThresholdResetRateLimitResponses;
/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.endpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 *
 * @returns - A promise that resolves when the rate limit is reset successfully.
 */
const resetRateLimits = async (params) => {
    const { authTokens, endpointsMap, verifier, verifierId } = params;
    if (authTokens.length === 0) {
        throw new Error('No auth tokens provided');
    }
    if (Object.keys(endpointsMap).length === 0) {
        throw new Error('No endpoints provided');
    }
    if (authTokens.length < 3) {
        throw new Error('At least 3 auth tokens are required');
    }
    // TODO: get signature and signedData from the user authentication key.
    const signature = '0x';
    const signedData = JSON.stringify({
        node_index: 0,
        timestamp: Date.now(),
        action: 'reset_ratelimit',
    });
    const promiseArr = authTokens.map(async (authToken) => {
        const endpoint = endpointsMap[authToken.nodeIndex];
        if (!endpoint) {
            throw new Error(`Endpoint not found for node index ${authToken.nodeIndex}`);
        }
        const requestParams = (0, exports.createResetRateLimitRequestParams)(authToken.authToken, signature, signedData, verifier, verifierId);
        return (0, exports.createResetRateLimitRequest)(endpoint, requestParams);
    });
    const result = await (0, auth_network_utils_1.Some)(promiseArr, async (resultArr) => (0, exports.validateThresholdResetRateLimitResponses)(resultArr, authTokens.length));
    if (!result) {
        throw new Error('Insufficient reset rate limit request results');
    }
};
exports.resetRateLimits = resetRateLimits;
//# sourceMappingURL=resetRateLimits.cjs.map