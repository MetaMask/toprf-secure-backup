import type { JRPCResponse, JRPCRequest } from "@metamask/auth-network-utils";
export type CommitmentJRPCRequestParams = {
    messagePrefix: string;
    tokenCommitment: string;
    verifier: string;
    tempPubKeyX: string;
    tempPubKeyY: string;
};
export type CommitmentJRPCRequest = JRPCRequest<CommitmentJRPCRequestParams>;
export type CommitmentRequestResult = {
    signature: string;
    data: string;
    nodePubX: string;
    nodePubY: string;
    nodeIndex: number;
};
export type CommitmentJRPCResponse = JRPCResponse<CommitmentRequestResult>;
export type AuthJRPCRequestParams = {
    authData: {
        authenticationContext: {
            idToken: string;
            verifier: string;
            verifierId: string;
        };
        extraOauthParams?: Record<string, string | number | boolean>;
    };
    commitmentSignatures: CommitmentRequestResult[];
    clientTime: string;
};
export type AuthJRPCRequest = JRPCRequest<AuthJRPCRequestParams>;
export type AuthRequestResult = {
    authToken: string;
    nodeIndex: number;
    nodePubKey: string;
    pubKey: string;
    keyIndex: number;
};
export type AuthJRPCResponse = JRPCResponse<AuthRequestResult>;
export type ShareImportItem = {
    encryptedAuthToken: string;
    encryptedShare: string;
    shareKeyIndex: number;
    nodeIndex: number;
    sssEndpoint: string;
};
export type StoreKeySharesJRPCRequestParams = {
    verifier: string;
    verifierId: string;
    pubKey: string;
    shareImportItems: ShareImportItem[];
};
export type StoreKeySharesJRPCRequest = JRPCRequest<StoreKeySharesJRPCRequestParams>;
export type StoreKeySharesJRPCResponse = JRPCResponse<null>;
export type ResetRateLimitJRPCRequestParams = {
    authToken: string;
    signature: string;
    signedData: string;
    verifier: string;
    verifierId: string;
};
export type ResetRateLimitJRPCRequest = JRPCRequest<ResetRateLimitJRPCRequestParams>;
export type ResetRateLimitJRPCResponse = JRPCResponse<null>;
export type ToprfEvalJRPCRequestParams = {
    authToken: string;
    shareCoefficient: string;
    blindedInputX: string;
    blindedInputY: string;
    verifier: string;
    verifierId: string;
};
export type ToprfEvalJRPCRequest = JRPCRequest<ToprfEvalJRPCRequestParams>;
export type ToprfEvalResult = {
    blindedOutputX: string;
    blindedOutputY: string;
    nodeIndex: number;
    pubKey: string;
};
export type ToprfEvalJRPCResponse = JRPCResponse<ToprfEvalResult>;
//# sourceMappingURL=jrpcInterfaces.d.cts.map