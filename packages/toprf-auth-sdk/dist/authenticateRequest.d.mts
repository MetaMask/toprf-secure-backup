import type { AuthJRPCResponse, AuthJRPCRequestParams, CommitmentRequestResult, AuthRequestResult } from "./jrpcInterfaces.mjs";
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
export declare const createAuthenticateRequestParams: (idToken: string, verifier: string, verifierID: string, commitmentSignatures: CommitmentRequestResult[]) => AuthJRPCRequestParams;
/**
 * Creates a authenticate request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the authenticate request
 * @param params - The parameters for the authenticate request
 * @returns The authenticate request promise.
 */
export declare const createAuthenticateRequest: (endpoint: string, params: AuthJRPCRequestParams) => Promise<AuthJRPCResponse>;
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
export declare const authenticateUser: (params: {
    idToken: string;
    verifier: string;
    verifierID: string;
    sessionPrivateKey: string;
    endpoints: string[];
    commitmentSignatures: CommitmentRequestResult[];
}) => Promise<AuthRequestResult[]>;
//# sourceMappingURL=authenticateRequest.d.mts.map