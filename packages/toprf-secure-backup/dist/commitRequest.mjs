import { Some, keccak256AndHexify, retryPromiseWithBackoff } from "@metamask/auth-network-utils";
import { generateJsonRPCObject } from "@toruslabs/http-helpers";
import { COMMIT_RESPONSE_THRESHOLD, COMMIT_RETRY_COUNT, JRPC_METHODS } from "./constants.mjs";
import { postJRPCRequest } from "./utils.mjs";
/**
 * Creates the parameters for the commitment request.
 *
 * @param tokenCommitment - The token commitment, hash of the idToken (without 0x prefix).
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment JRPC request.
 */
export const createCommitmentRequestParams = (tokenCommitment, verifier, sessionPubKeyX, sessionPubKeyY) => {
    return {
        messagePrefix: 'mug00',
        tokenCommitment,
        verifier,
        tempPubKeyX: sessionPubKeyX,
        tempPubKeyY: sessionPubKeyY,
    };
};
/**
 * Sends a commitment request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the commitment request.
 * @param params - The parameters for the commitment request.
 * @returns The commitment responses.
 */
export const sendCommitmentRequest = async (endpoint, params) => {
    const commitmentJRPCRequest = generateJsonRPCObject(JRPC_METHODS.COMMITMENT_REQUEST, params);
    /**
     * Sends the commitment request to the given endpoint and returns the commitment response.
     *
     * @returns The commitment response.
     */
    const commitmentResponse = async () => postJRPCRequest(endpoint, commitmentJRPCRequest);
    return retryPromiseWithBackoff(commitmentResponse, COMMIT_RETRY_COUNT);
};
/**
 * Validates the commitment responses.
 *
 * @param resultArr - The commitment request result.
 * @returns The commitment request result.
 */
export const validateThresholdCommitmentResponses = async (resultArr) => {
    const completedRequests = resultArr.filter((res) => {
        if (!res || typeof res !== 'object') {
            return false;
        }
        if ('error' in res && res.error) {
            return false;
        }
        return true;
    });
    if (completedRequests.length < COMMIT_RESPONSE_THRESHOLD) {
        return Promise.reject(new Error(`Not enough completed requests. Expected: ${COMMIT_RESPONSE_THRESHOLD}, got: ${completedRequests.length}, ${JSON.stringify(resultArr)}`));
    }
    return completedRequests
        .filter((res) => res.result)
        .map((res) => res.result);
};
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
export const commitIdToken = async (params) => {
    const { idToken, endpoints, verifier, sessionPubKeyX, sessionPubKeyY } = params;
    const tokenCommitment = keccak256AndHexify(new TextEncoder().encode(idToken)).slice(2);
    const requestParams = createCommitmentRequestParams(tokenCommitment, verifier, sessionPubKeyX, sessionPubKeyY);
    const promiseArr = endpoints.map(async (endpoint) => sendCommitmentRequest(endpoint, requestParams));
    const resultArr = await Some(promiseArr, async (results) => validateThresholdCommitmentResponses(results));
    if (!resultArr || resultArr.length === 0) {
        throw new Error('No commitment request results');
    }
    return resultArr;
};
//# sourceMappingURL=commitRequest.mjs.map