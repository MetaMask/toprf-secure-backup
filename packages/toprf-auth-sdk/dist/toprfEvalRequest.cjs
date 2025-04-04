"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recoverTOPRFSeed = exports.evaluateSeed = exports.createToprfEvalRequest = exports.createToprfEvalRequestParams = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const http_helpers_1 = require("@toruslabs/http-helpers");
const keccak_1 = require("ethereum-cryptography/keccak");
const secp256k1_1 = require("ethereum-cryptography/secp256k1");
const constants_1 = require("./constants.cjs");
const keyDerivation_1 = require("./keyDerivation.cjs");
const oprf_1 = require("./oprf.cjs");
const utils_1 = require("./utils.cjs");
/**
 * Creates the parameters for the toprf eval request
 *
 * @param authToken - The auth issued by node to authenticate the request.
 * @param blindedInputX - The blinded input x.
 * @param blindedInputY - The blinded input y.
 * @param verifier - The verifier name.
 * @param verifierId - The verifier id of the user.
 *
 * @returns The parameters for the toprf eval jrpc request.
 */
const createToprfEvalRequestParams = (authToken, blindedInputX, blindedInputY, verifier, verifierId) => {
    return {
        authToken,
        shareCoefficient: '1',
        blindedInputX,
        blindedInputY,
        verifier,
        verifierId,
    };
};
exports.createToprfEvalRequestParams = createToprfEvalRequestParams;
/**
 * Creates a toprf eval request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the toprf eval request
 * @param params - The parameters for the toprf eval request
 * @returns Array of toprf eval request promises
 */
const createToprfEvalRequest = async (endpoint, params) => {
    const toprfEvalJRPCRequest = (0, http_helpers_1.generateJsonRPCObject)(constants_1.JRPC_METHODS.TOPRF_EVAL_REQUEST, params);
    /**
     * Sends the toprf eval request to the given endpoint and returns the toprf eval response.
     *
     * @returns The toprf eval response.
     */
    const toprfEvalResponse = (0, utils_1.postJRPCRequest)(endpoint, toprfEvalJRPCRequest);
    return toprfEvalResponse;
};
exports.createToprfEvalRequest = createToprfEvalRequest;
/**
 * Evaluates the seed from the toprf eval responses
 *
 * @param hashedInput - The hashed input i.e. hash of the password.
 * @param randomScalar - The random scalar used to blind the input.
 * @param resultArr - The toprf eval request result
 * @param threshold - Mininum number of valid responses required to evaluate key using toprf.
 * @returns The toprf eval request result
 */
const evaluateSeed = async (hashedInput, randomScalar, resultArr, threshold) => {
    const completedRequests = resultArr.filter((res) => {
        if (!res || typeof res !== 'object') {
            return false;
        }
        if ('error' in res && res.error) {
            return false;
        }
        return true;
    });
    console.log('completedRequests a', completedRequests.length);
    if (completedRequests.length >= threshold) {
        const thresholdAuthPubKey = (0, auth_network_utils_1.thresholdSame)(completedRequests.map((res) => res.result?.pubKey), threshold);
        console.log('thresholdAuthPubKey', thresholdAuthPubKey);
        if (thresholdAuthPubKey) {
            const blindedServerPoints = completedRequests
                .map((resp) => {
                const { blindedOutputX, blindedOutputY, nodeIndex } = resp.result ?? {};
                // Check if all required values are defined
                if (!blindedOutputX || !blindedOutputY || !nodeIndex) {
                    return null;
                }
                return {
                    x: blindedOutputX,
                    y: blindedOutputY,
                    nodeIndex,
                };
            })
                .filter((point) => point !== null);
            // evaluate auth priv key using oprf and match with the threshold auth pub key
            const allCombis = (0, auth_network_utils_1.kCombinations)(completedRequests.length, threshold);
            let seed = null;
            for (const currentCombi of allCombis) {
                const currentCombiPoints = blindedServerPoints.filter((_, index) => currentCombi.includes(index));
                const curvePoints = currentCombiPoints.map((point) => secp256k1_1.secp256k1.ProjectivePoint.fromHex(`04${point.x}${point.y}`));
                const nodeIndexes = currentCombiPoints.map((point) => BigInt(point.nodeIndex));
                // Interpolate the curve points directly using Lagrange interpolation
                const reconstructedPoint = (0, auth_network_utils_1.lagrangeInterpolationForPoints)(secp256k1_1.secp256k1.CURVE.n, curvePoints, nodeIndexes);
                // Unblind and hash the result
                const recoveredSeed = oprf_1.OPRF.unblindAndHash(hashedInput, reconstructedPoint, randomScalar);
                console.log('recoveredSeed', recoveredSeed);
                const { pk } = (0, keyDerivation_1.deriveAuthenticationKeyPair)(recoveredSeed);
                const authPubKey = (0, auth_network_utils_1.pubKeyToSec1)(pk);
                if (authPubKey === thresholdAuthPubKey) {
                    seed = recoveredSeed;
                    break;
                }
            }
            if (!seed) {
                throw new Error('could not derive encryption key');
            }
            return Promise.resolve(seed);
        }
    }
    return Promise.reject(new Error(`invalid toprf eval results ${JSON.stringify(resultArr)}`));
};
exports.evaluateSeed = evaluateSeed;
/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.endpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 *
 * @param params.password - The password of the user.
 * @returns - A promise that resolves with the key pair seed successfully.
 */
const recoverTOPRFSeed = async (params) => {
    const { authTokens, endpointsMap, verifier, verifierId, password } = params;
    if (authTokens.length === 0) {
        throw new Error('No auth tokens provided');
    }
    if (Object.keys(endpointsMap).length === 0) {
        throw new Error('No endpoints provided');
    }
    if (authTokens.length < 3) {
        throw new Error('At least 3 auth tokens are required');
    }
    const passwordBytes = new TextEncoder().encode(password);
    const hashedInput = (0, keccak_1.keccak256)(passwordBytes);
    const { a, r } = oprf_1.OPRF.blind(hashedInput);
    const promiseArr = authTokens.map(async (authToken) => {
        const endpoint = endpointsMap[authToken.nodeIndex];
        if (!endpoint) {
            throw new Error(`Endpoint not found for node index ${authToken.nodeIndex}`);
        }
        const requestParams = (0, exports.createToprfEvalRequestParams)(authToken.authToken, a.x.toString(16), a.y.toString(16), verifier, verifierId);
        return (0, exports.createToprfEvalRequest)(endpoint, requestParams);
    });
    const result = await (0, auth_network_utils_1.Some)(promiseArr, async (resultArr) => (0, exports.evaluateSeed)(hashedInput, r, resultArr, 3));
    if (!result) {
        throw new Error('Insufficient toprf eval request results');
    }
    return result;
};
exports.recoverTOPRFSeed = recoverTOPRFSeed;
//# sourceMappingURL=toprfEvalRequest.cjs.map