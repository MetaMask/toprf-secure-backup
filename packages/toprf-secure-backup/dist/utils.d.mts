import type { JRPCRequest, JSONValue } from "@metamask/auth-network-utils";
import BN from "bn.js";
import type { NodeAuthTokens } from "./interfaces.mjs";
import type { ShareImportItem } from "./jrpcInterfaces.mjs";
/**
 * Converts a BigInt to BN
 *
 * @param value - BigInt value to convert
 * @returns BN instance
 */
export declare const bigIntToBN: (value: bigint) => BN;
/**
 * Common post function that handles snake_case conversion of request params
 * and camelCase conversion of response result.
 *
 * @param endpoint - The endpoint to make the request to
 * @param request - The request object to send. The params are converted to snake_case.
 *
 * @returns The response with camelCase converted result
 */
export declare const postJRPCRequest: <Response_1 extends {
    result?: JSONValue;
}>(endpoint: string, request: JRPCRequest<JSONValue>) => Promise<Response_1>;
/**
 * Decrypts the auth token using the session private key
 *
 * @param authToken - The auth token to be decrypted.
 * @param sessionPrivateKey - The session private key to be used for the decryption.
 *
 * @returns The decrypted auth token.
 */
export declare const decryptAuthToken: (authToken: string, sessionPrivateKey: Uint8Array) => Promise<string>;
/**
 * Generates encrypted share import items for each node
 *
 * @param nodeEndpointsMap - Map of node indexes to endpoints.
 * @param authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param privKey - The private key to be used for the share import items.
 * @param keyIndex - The key index to be used for the share import items.
 *
 * @returns The share import items containing the encrypted shares, the key index, the node index, and the sss endpoint.
 */
export declare const generateShareImportItems: (nodeEndpointsMap: Record<number, string>, authTokens: NodeAuthTokens, privKey: bigint, keyIndex: number) => Promise<ShareImportItem[]>;
//# sourceMappingURL=utils.d.mts.map