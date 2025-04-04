import { Some, keccak256AndHexify, retryPromiseWithBackoff } from "@metamask/auth-network-utils";
import { generateJsonRPCObject } from "@toruslabs/http-helpers";
import { JRPC_METHODS } from "./constants.mjs";
import { postJRPCRequest } from "./utils.mjs";
/**
 * Creates the parameters for the commitment request
 *
 * @param tokenCommitment - The token commitment, hash of the idToken
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment jrpc request
 */
export const createCommitmentRequestParams = (tokenCommitment, verifier, sessionPubKeyX, sessionPubKeyY) => {
    return {
        messagePrefix: 'mug00',
        tokenCommitment: tokenCommitment.slice(2),
        verifier,
        tempPubKeyX: sessionPubKeyX,
        tempPubKeyY: sessionPubKeyY,
    };
};
/**
 * Creates a commitment request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the commitment request
 * @param params - The parameters for the commitment request
 * @returns Array of commitment request promises
 */
export const createCommitmentRequest = async (endpoint, params) => {
    const commitmentJRPCRequest = generateJsonRPCObject(JRPC_METHODS.COMMITMENT_REQUEST, params);
    /**
     * Sends the commitment request to the given endpoint and returns the commitment response.
     *
     * @returns The commitment response.
     */
    const commitmentResponse = async () => postJRPCRequest(endpoint, commitmentJRPCRequest);
    return retryPromiseWithBackoff(commitmentResponse, 4);
};
/**
 * Validates the commitment responses
 *
 * @param resultArr - The commitment request result
 * @param threeFourthsThreshold - The threshold for the number commitment responses to be valid
 * @returns The commitment request result
 */
export const validateThresholdCommitmentResponses = async (resultArr, threeFourthsThreshold) => {
    const completedRequests = resultArr.filter((res) => {
        if (!res || typeof res !== 'object') {
            return false;
        }
        if ('error' in res && res.error) {
            return false;
        }
        return true;
    });
    if (completedRequests.length >= threeFourthsThreshold) {
        const requiredNodeResult = completedRequests.find((resp) => resp !== undefined && 'result' in resp);
        if (requiredNodeResult) {
            const validResultArr = completedRequests.filter((res) => res.result);
            return Promise.resolve(validResultArr.map((res) => res.result));
        }
    }
    return Promise.reject(new Error(`invalid commitment results ${JSON.stringify(resultArr)}`));
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
 * @param params.indexes - The indexes to be used for the commitment request
 * @returns resultArr - The commitment request result, where each element is
 * a signed commitment data from a node.
 */
export const commitmentRequest = async (params) => {
    const { idToken, endpoints, verifier, sessionPubKeyX, sessionPubKeyY } = params;
    const threeFourthsThreshold = Math.floor((endpoints.length * 3) / 4) + 1;
    const tokenCommitment = keccak256AndHexify(new TextEncoder().encode(idToken));
    const requestParams = createCommitmentRequestParams(tokenCommitment, verifier, sessionPubKeyX, sessionPubKeyY);
    const promiseArr = endpoints.map(async (endpoint) => createCommitmentRequest(endpoint, requestParams));
    return new Promise((resolve, reject) => {
        Some(promiseArr, async (resultArr) => validateThresholdCommitmentResponses(resultArr, threeFourthsThreshold))
            .then((resultArr) => {
            if (!resultArr || resultArr.length === 0) {
                throw new Error('No commitment request results');
            }
            else {
                return resolve(resultArr);
            }
        })
            .catch(reject);
    });
};
//# sourceMappingURL=commitmentRequest.mjs.map