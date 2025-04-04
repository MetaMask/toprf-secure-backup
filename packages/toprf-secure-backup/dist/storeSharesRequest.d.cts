import type { NodeAuthTokens } from "./interfaces.cjs";
import type { StoreKeySharesJRPCRequestParams, StoreKeySharesJRPCResponse } from "./jrpcInterfaces.cjs";
export type CreateStoreKeySharesRequestParamsInput = {
    nodeEndpointsMap: Record<number, string>;
    authTokens: NodeAuthTokens;
    keyIndex: number;
    verifier: string;
    verifierId: string;
    oprfKey: bigint;
    authPubKey: Uint8Array;
};
export type StoreKeySharesRequestParams = CreateStoreKeySharesRequestParamsInput;
/**
 * Creates the parameters for the store key shares request
 *
 * @param params - The parameters for the store key shares request.
 * @param params.nodeEndpointsMap - The map of node indexes to endpoints.
 * @param params.authTokens - The authTokens to be used for the store key shares request.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.authPubKey - The auth pubkey associated with the authentication key pair derived from the seed and input.
 *
 * @returns The parameters for the store key shares request
 */
export declare const createStoreKeySharesRequestParams: (params: CreateStoreKeySharesRequestParamsInput) => Promise<StoreKeySharesJRPCRequestParams>;
/**
 * Sends a store key shares request to the given endpoint.
 *
 * @param endpoint - The endpoint to be used for the store key shares request.
 * @param params - The parameters for the store key shares request.
 *
 * @returns The store key shares request promise.
 */
export declare const sendStoreKeySharesRequest: (endpoint: string, params: StoreKeySharesJRPCRequestParams) => Promise<StoreKeySharesJRPCResponse>;
/**
 * Stores the key shares for the given node endpoints
 *
 * @param params - The parameters for the store key shares request
 * @param params.nodeEndpointsMap - The node endpoints map to be used for the store key shares request.
 * @param params.verifier - The verifier to be used for the store key shares request.
 * @param params.verifierId - The verifierId to be used for the store key shares request.
 * @param params.authTokens - The authTokens issued by the nodes on authenticating the user.
 * @param params.keyIndex - The key index to be used for the store key shares request.
 * KeyIndex should be 1 for the first key registration and derived from response of authenticate request for subsequent key registrations.
 *
 * @param params.oprfKey - The oprfKey to be used for the store key shares request.
 * @param params.authPubKey - The  auth pubkey associated with the authentication key pair derived from the seed and input.
 *
 * @returns The store key shares request promise.
 */
export declare const storeKeyShares: (params: StoreKeySharesRequestParams) => Promise<StoreKeySharesJRPCResponse>;
//# sourceMappingURL=storeSharesRequest.d.cts.map