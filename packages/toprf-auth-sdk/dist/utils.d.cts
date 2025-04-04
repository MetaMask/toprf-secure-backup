import type { JRPCRequest, JSONValue } from "@metamask/auth-network-utils";
import type { INodePub } from "@toruslabs/constants";
import BN from "bn.js";
import type { NodeAuthToken } from "./interfaces.cjs";
import type { ShareImportItem } from "./jrpcInterfaces.cjs";
/**
 * Converts a BigInt to BN
 *
 * @param value - BigInt value to convert
 * @returns BN instance
 */
export declare const bigIntToBN: (value: bigint) => BN;
/**
 * Randomly selects a node URL from the available nodes
 *
 * @returns An object containing:
 * - url: The URL of the randomly selected node
 * - index: The 1-based index of the selected node
 */
export declare const getRandomNode: () => {
    url: string;
    index: string;
};
/**
 * Generates encrypted share import items for each node
 *
 * @param nodeIndexes - The node indexes to be used for the share import items.
 * @param nodePubkeys - The node public keys to be used for the share import items.
 * @param authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param privKey - The private key to be used for the share import items.
 * @param keyIndex - The key index to be used for the share import items.
 *
 * @returns The share import items containing the encrypted shares, the key index, the node index, and the sss endpoint.
 */
export declare const generateShareImportItems: (nodeIndexes: number[], nodePubkeys: INodePub[], authTokens: NodeAuthToken[], privKey: bigint, keyIndex: number) => Promise<ShareImportItem[]>;
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
export declare const decryptAuthToken: (authToken: string, sessionPrivateKey: string) => Promise<string>;
//# sourceMappingURL=utils.d.cts.map