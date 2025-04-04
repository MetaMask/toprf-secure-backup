"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.commitIdToken = exports.validateThresholdCommitmentResponses = exports.sendCommitmentRequest = exports.createCommitmentRequestParams = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const http_helpers_1 = require("@toruslabs/http-helpers");
const constants_1 = require("./constants.cjs");
const utils_1 = require("./utils.cjs");
/**
 * Creates the parameters for the commitment request.
 *
 * @param tokenCommitment - The token commitment, hash of the idToken (without 0x prefix).
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment JRPC request.
 */
const createCommitmentRequestParams = (tokenCommitment, verifier, sessionPubKeyX, sessionPubKeyY) => {
    return {
        messagePrefix: 'mug00',
        tokenCommitment,
        verifier,
        tempPubKeyX: sessionPubKeyX,
        tempPubKeyY: sessionPubKeyY,
    };
};
exports.createCommitmentRequestParams = createCommitmentRequestParams;
/**
 * Sends a commitment request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the commitment request.
 * @param params - The parameters for the commitment request.
 * @returns The commitment responses.
 */
const sendCommitmentRequest = async (endpoint, params) => {
    const commitmentJRPCRequest = (0, http_helpers_1.generateJsonRPCObject)(constants_1.JRPC_METHODS.COMMITMENT_REQUEST, params);
    /**
     * Sends the commitment request to the given endpoint and returns the commitment response.
     *
     * @returns The commitment response.
     */
    const commitmentResponse = async () => (0, utils_1.postJRPCRequest)(endpoint, commitmentJRPCRequest);
    return (0, auth_network_utils_1.retryPromiseWithBackoff)(commitmentResponse, constants_1.COMMIT_RETRY_COUNT);
};
exports.sendCommitmentRequest = sendCommitmentRequest;
/**
 * Validates the commitment responses.
 *
 * @param resultArr - The commitment request result.
 * @returns The commitment request result.
 */
const validateThresholdCommitmentResponses = async (resultArr) => {
    const completedRequests = resultArr.filter((res) => {
        if (!res || typeof res !== 'object') {
            return false;
        }
        if ('error' in res && res.error) {
            return false;
        }
        return true;
    });
    if (completedRequests.length < constants_1.COMMIT_RESPONSE_THRESHOLD) {
        return Promise.reject(new Error(`Not enough completed requests. Expected: ${constants_1.COMMIT_RESPONSE_THRESHOLD}, got: ${completedRequests.length}, ${JSON.stringify(resultArr)}`));
    }
    return completedRequests
        .filter((res) => res.result)
        .map((res) => res.result);
};
exports.validateThresholdCommitmentResponses = validateThresholdCommitmentResponses;
/**
 * Creates a commitment request to the given endpoints and validates the responses
 *
 * @param params - The parameters for the commitment request
 * @param params.idToken - The idToken to be used for the commitment request
 * @param params.verifier - The verifier to be used for the commitment request
 * @param params.sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param params.sessionPubKeyY - The public key y to be used for the commitment request session.
 * @param params.endpoints - The endpoints to be used for the commitment request
 * @returns resultArr - The commitment request result, where each element is
 * a signed commitment data from a node.
 */
const commitIdToken = async (params) => {
    const { idToken, endpoints, verifier, sessionPubKeyX, sessionPubKeyY } = params;
    const tokenCommitment = (0, auth_network_utils_1.keccak256AndHexify)(new TextEncoder().encode(idToken)).slice(2);
    const requestParams = (0, exports.createCommitmentRequestParams)(tokenCommitment, verifier, sessionPubKeyX, sessionPubKeyY);
    const promiseArr = endpoints.map(async (endpoint) => (0, exports.sendCommitmentRequest)(endpoint, requestParams));
    const resultArr = await (0, auth_network_utils_1.Some)(promiseArr, async (results) => (0, exports.validateThresholdCommitmentResponses)(results));
    if (!resultArr || resultArr.length === 0) {
        throw new Error('No commitment request results');
    }
    return resultArr;
};
exports.commitIdToken = commitIdToken;
//# sourceMappingURL=commitRequest.cjs.map