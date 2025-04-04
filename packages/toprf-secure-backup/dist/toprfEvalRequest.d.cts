import type { NodeAuthTokens } from "./interfaces.cjs";
import type { ToprfEvalJRPCRequestParams, ToprfEvalJRPCResponse } from "./jrpcInterfaces.cjs";
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
export declare const createToprfEvalRequestParams: (authToken: string, blindedInputX: string, blindedInputY: string, verifier: string, verifierId: string) => ToprfEvalJRPCRequestParams;
/**
 * Creates a toprf eval request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the toprf eval request
 * @param params - The parameters for the toprf eval request
 * @returns Array of toprf eval request promises
 */
export declare const createToprfEvalRequest: (endpoint: string, params: ToprfEvalJRPCRequestParams) => Promise<ToprfEvalJRPCResponse>;
/**
 * Evaluates the seed from the toprf eval responses
 *
 * @param hashedInput - The hashed input i.e. hash of the password.
 * @param randomScalar - The random scalar used to blind the input.
 * @param resultArr - The toprf eval request result
 * @returns The toprf eval request result
 */
export declare const evaluateSeed: (hashedInput: Uint8Array, randomScalar: bigint, resultArr: ToprfEvalJRPCResponse[]) => Promise<Uint8Array>;
/**
 * Resets the rate limit of user's authentication key recovery attempts.
 *
 * @param params - The parameters for the reset rate limit request
 * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param params.verifier - The verifier name used for authentication.
 * @param params.verifierId - The verifierId issued to user after authentication.
 * @param params.nodeEndpointsMap - Map of node index to endpoint to be used for the reset rate limit request.
 * @param params.userPasswordHash - The password of the user.
 *
 * @returns - A promise that resolves with the key pair seed successfully.
 */
export declare const recoverTOPRFSeed: (params: {
    authTokens: NodeAuthTokens;
    nodeEndpointsMap: Record<number, string>;
    verifier: string;
    verifierId: string;
    userPasswordHash: Uint8Array;
}) => Promise<Uint8Array>;
//# sourceMappingURL=toprfEvalRequest.d.cts.map