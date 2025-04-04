import type { CommitmentJRPCRequestParams, CommitmentJRPCResponse, CommitmentRequestResult } from "./jrpcInterfaces.cjs";
/**
 * Creates the parameters for the commitment request
 *
 * @param tokenCommitment - The token commitment, hash of the idToken
 * @param verifier - The verifier
 * @param sessionPubKeyX - The public key x to be used for the commitment request session.
 * @param sessionPubKeyY - The public key y to be used for the commitment request session.
 * @returns The parameters for the commitment jrpc request
 */
export declare const createCommitmentRequestParams: (tokenCommitment: string, verifier: string, sessionPubKeyX: string, sessionPubKeyY: string) => CommitmentJRPCRequestParams;
/**
 * Creates a commitment request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the commitment request
 * @param params - The parameters for the commitment request
 * @returns Array of commitment request promises
 */
export declare const createCommitmentRequest: (endpoint: string, params: CommitmentJRPCRequestParams) => Promise<CommitmentJRPCResponse>;
/**
 * Validates the commitment responses
 *
 * @param resultArr - The commitment request result
 * @param threeFourthsThreshold - The threshold for the number commitment responses to be valid
 * @returns The commitment request result
 */
export declare const validateThresholdCommitmentResponses: (resultArr: CommitmentJRPCResponse[], threeFourthsThreshold: number) => Promise<CommitmentRequestResult[]>;
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
export declare const commitmentRequest: (params: {
    idToken: string;
    verifier: string;
    sessionPubKeyX: string;
    sessionPubKeyY: string;
    endpoints: string[];
    indexes: number[];
}) => Promise<CommitmentRequestResult[]>;
//# sourceMappingURL=commitmentRequest.d.cts.map