import { Some, thresholdSame } from "@metamask/auth-network-utils";
import { generateJsonRPCObject } from "@toruslabs/http-helpers";
import { JRPC_METHODS } from "./constants.mjs";
import { decryptAuthToken, postJRPCRequest } from "./utils.mjs";
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
export const createAuthenticateRequestParams = (idToken, verifier, verifierID, commitmentSignatures) => {
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
 * Creates a authenticate request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @returns The authenticate request promise.
 */
export const createAuthenticateRequest = async (endpoint, params) => {
    const authJRPCRequest = generateJsonRPCObject(JRPC_METHODS.AUTHENTICATE_REQUEST, params);
    /**
     * Sends the authenticate request to the given endpoint and returns the authenticate response.
     *
     * @returns The authenticate response.
     */
    const authRequestPromise = async () => postJRPCRequest(endpoint, authJRPCRequest);
    return authRequestPromise();
};
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
        const thresholdPubData = thresholdSame(pubData, threshold);
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
export const authenticateUser = async (params) => {
    const { idToken, endpoints, verifier, verifierID, commitmentSignatures, sessionPrivateKey, } = params;
    const requestParams = createAuthenticateRequestParams(idToken, verifier, verifierID, commitmentSignatures);
    const promiseArr = endpoints.map(async (endpoint) => createAuthenticateRequest(endpoint, requestParams));
    const results = await new Promise((resolve, reject) => {
        Some(promiseArr, async (resultArr) => validateThresholdAuthenticateResponses(resultArr, endpoints.length))
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
        const decryptedAuthToken = await decryptAuthToken(authToken, sessionPrivateKey);
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
//# sourceMappingURL=authenticateRequest.mjs.map