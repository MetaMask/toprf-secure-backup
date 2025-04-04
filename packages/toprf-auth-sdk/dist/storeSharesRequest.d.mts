import type { INodePub } from "@toruslabs/constants";
import type { NodeAuthTokens } from "./interfaces.mjs";
import type { StoreKeySharesJRPCRequestParams, StoreKeySharesJRPCResponse } from "./jrpcInterfaces.mjs";
export type CreateStoreKeySharesRequestParamsInput = {
    nodeIndexes: number[];
    nodePubkeys: INodePub[];
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
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
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
 * Creates a store key shares request to the given endpoint
 *
 * @param endpoint - The endpoint to be used for the store key shares request
 * @param params - The parameters for the store key shares request
 * @returns The store key shares request promise.
 */
export declare const createStoreKeySharesRequest: (endpoint: string, params: StoreKeySharesJRPCRequestParams) => Promise<StoreKeySharesJRPCResponse>;
/**
 * Stores the key shares for the given node endpoints
 *
 * @param nodeEndpoints - The node endpoints to be used for the store key shares request.
 *
 * @param params - The parameters for the store key shares request
 * @param params.nodeIndexes - The node indexes to be used for the store key shares request.
 * @param params.nodePubkeys - The node pubkeys to be used for the store key shares request.
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
export declare const storeKeyShares: (nodeEndpoints: string[], params: StoreKeySharesRequestParams) => Promise<StoreKeySharesJRPCResponse>;
//# sourceMappingURL=storeSharesRequest.d.mts.map