import type { AuthJRPCResponse, CommitmentRequestResult, AuthRequestResult } from "./jrpcInterfaces.mjs";
/**
 * Validates the authenticate responses
 *
 * @param resultArr - The authenticate request result
 * @returns The authenticate request result
 */
export declare const validateThresholdAuthenticateResponses: (resultArr: AuthJRPCResponse[]) => Promise<AuthRequestResult[]>;
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
    sessionPrivateKey: Uint8Array;
    endpoints: string[];
    commitmentSignatures: CommitmentRequestResult[];
}) => Promise<AuthRequestResult[]>;
//# sourceMappingURL=authenticateRequest.d.mts.map