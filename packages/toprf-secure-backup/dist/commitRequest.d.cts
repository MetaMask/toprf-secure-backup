import type { CommitmentJRPCRequestParams, CommitmentJRPCResponse, CommitmentRequestResult } from "./jrpcInterfaces.cjs";
/**
 * Creates the parameters for the commitment request.
 *
 * @param tokenCommitment - The token commitment, hash of the idToken (without 0x prefix).
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment JRPC request.
 */
export declare const createCommitmentRequestParams: (tokenCommitment: string, verifier: string, sessionPubKeyX: string, sessionPubKeyY: string) => CommitmentJRPCRequestParams;
/**
 * Sends a commitment request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the commitment request.
 * @param params - The parameters for the commitment request.
 * @returns The commitment responses.
 */
export declare const sendCommitmentRequest: (endpoint: string, params: CommitmentJRPCRequestParams) => Promise<CommitmentJRPCResponse>;
/**
 * Validates the commitment responses.
 *
 * @param resultArr - The commitment request result.
 * @returns The commitment request result.
 */
export declare const validateThresholdCommitmentResponses: (resultArr: CommitmentJRPCResponse[]) => Promise<CommitmentRequestResult[]>;
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
export declare const commitIdToken: (params: {
    idToken: string;
    verifier: string;
    sessionPubKeyX: string;
    sessionPubKeyY: string;
    endpoints: string[];
}) => Promise<CommitmentRequestResult[]>;
//# sourceMappingURL=commitRequest.d.cts.map