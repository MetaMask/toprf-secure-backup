import type { NodeAuthTokens } from "./interfaces.mjs";
import type { ResetRateLimitJRPCRequestParams, ResetRateLimitJRPCResponse } from "./jrpcInterfaces.mjs";
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
export declare const createResetRateLimitRequestParams: (authToken: string, signature: string, signedData: string, verifier: string, verifierId: string) => ResetRateLimitJRPCRequestParams;
/**
 * Sends a reset rate limit request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the reset rate limit request
 * @param params - The parameters for the reset rate limit request
 * @returns promise of reset rate limit response.
 */
export declare const sendResetRateLimitRequest: (endpoint: string, params: ResetRateLimitJRPCRequestParams) => Promise<ResetRateLimitJRPCResponse>;
/**
 * Validates the reset rate limit responses
 *
 * @param resultArr - The reset rate limit request result
 * @param threshold - The threshold for the number reset rate limit responses to be valid
 * @returns The reset rate limit request result
 */
export declare const validateThresholdResetRateLimitResponses: (resultArr: ResetRateLimitJRPCResponse[], threshold: number) => Promise<boolean>;
/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 *
 * @returns - A promise that resolves when the rate limit is reset successfully.
 */
export declare const resetRateLimits: (params: {
    authTokens: NodeAuthTokens;
    nodeEndpointsMap: Record<number, string>;
    verifier: string;
    verifierId: string;
}) => Promise<void>;
//# sourceMappingURL=resetRateLimits.d.mts.map