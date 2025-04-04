"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateShareImportItems = exports.decryptAuthToken = exports.postJRPCRequest = exports.bigIntToBN = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const eccrypto_1 = require("@toruslabs/eccrypto");
const http_helpers_1 = require("@toruslabs/http-helpers");
const bn_js_1 = __importDefault(require("bn.js"));
/**
 * Converts a BigInt to BN
 *
 * @param value - BigInt value to convert
 * @returns BN instance
 */
const bigIntToBN = (value) => {
    return new bn_js_1.default(value.toString());
};
exports.bigIntToBN = bigIntToBN;
/**
 * Common post function that handles snake_case conversion of request params
 * and camelCase conversion of response result.
 *
 * @param endpoint - The endpoint to make the request to
 * @param request - The request object to send. The params are converted to snake_case.
 *
 * @returns The response with camelCase converted result
 */
const postJRPCRequest = async (endpoint, request) => {
    const req = { ...request };
    const params = (0, auth_network_utils_1.toSnakeCaseKeys)(request.params);
    req.params = params;
    return (0, http_helpers_1.post)(endpoint, req, {}, { logTracingHeader: false }).then((res) => {
        if (res.result) {
            res.result = (0, auth_network_utils_1.toCamelCaseKeys)(res.result);
        }
        return res;
    });
};
exports.postJRPCRequest = postJRPCRequest;
/**
 * Decrypts the auth token using the session private key
 *
 * @param authToken - The auth token to be decrypted.
 * @param sessionPrivateKey - The session private key to be used for the decryption.
 *
 * @returns The decrypted auth token.
 */
const decryptAuthToken = async (authToken, sessionPrivateKey) => {
    const authTokenData = JSON.parse(authToken);
    const metadata = (0, auth_network_utils_1.encParamsHexToBuf)(authTokenData.metadata);
    const decryptedAuthToken = await (0, eccrypto_1.decrypt)(Buffer.from(sessionPrivateKey), {
        ...metadata,
        ciphertext: Buffer.from(authTokenData.data, 'hex'),
    });
    return Buffer.from(decryptedAuthToken).toString('base64');
};
exports.decryptAuthToken = decryptAuthToken;
/**
 * Generates len(nodeIndexes) number of shares for a given private key with a given threshold.
 *
 * @param ecCurve - The elliptic curve to be used for the secret sharing.
 * @param nodeIndexes - The node indexes to be used for the secret sharing.
 * @param privKey - The private key to be used for secret sharing.
 * @param threshold - The threshold for the secret sharing.
 *
 * @returns Map of node indexes to shares.
 */
const generateShares = (ecCurve, nodeIndexes, privKey, threshold) => {
    const nodeIndexesBn = nodeIndexes.map((index) => new bn_js_1.default(index));
    const degree = threshold - 1;
    const poly = (0, auth_network_utils_1.generateRandomPolynomial)(ecCurve, degree, privKey);
    return poly.generateShares(nodeIndexesBn);
};
/**
 * Encrypts given data using pub key.
 *
 * @param data - Data to be encrypted in buffer format.
 * @param pubKey - Encryption pub key buffer.
 * @returns The encrypted data, encrypted with the given node's public key.
 */
const encryptData = async (data, pubKey) => {
    const encryptedData = await (0, eccrypto_1.encrypt)(pubKey, data);
    const encryptedDataHex = (0, auth_network_utils_1.encryptedParamsBufToHex)(encryptedData);
    return {
        data: Buffer.from(encryptedData.ciphertext).toString('hex'),
        metadata: {
            ...encryptedDataHex,
        },
    };
};
/**
 * Creates a share import item for a node
 *
 * @param encryptedShare - The encrypted share to be used for the share import item.
 * @param keyIndex - The key index to be used for the share import item.
 * @param authToken - The auth token of the node required for validating the user on backend.
 * @param nodePubKey - The public key of the node to be used for the share import item.
 * @param nodeIndex - The node index to be used for the share import item.
 * @param nodeEndpointsMap - Map of node indexes to endpoints.
 * @returns The share import item containing the encrypted share, the key index, the node index, and the sss endpoint.
 */
const createShareImportItem = async (encryptedShare, keyIndex, authToken, nodePubKey, nodeIndex, nodeEndpointsMap) => {
    const encryptedAuthToken = await encryptData(Buffer.from(authToken, 'base64'), nodePubKey);
    return {
        encryptedShare: JSON.stringify(encryptedShare),
        encryptedAuthToken: JSON.stringify(encryptedAuthToken),
        shareKeyIndex: keyIndex,
        nodeIndex,
        sssEndpoint: nodeEndpointsMap[nodeIndex],
    };
};
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
const generateShareImportItems = async (nodeEndpointsMap, authTokens, privKey, keyIndex) => {
    const privKeyBN = (0, exports.bigIntToBN)(privKey);
    const ecCurve = (0, auth_network_utils_1.getSecp256K1Curve)();
    const threshold = Math.floor(Object.values(nodeEndpointsMap).length / 2) + 1;
    const allNodeIndexes = Object.keys(nodeEndpointsMap).map((val) => parseInt(val, 10));
    // Generate shares for each node
    const shares = generateShares(ecCurve, allNodeIndexes, privKeyBN, threshold);
    // Encrypt shares for each node
    const encryptionPromises = authTokens.map(async (authTokenData) => {
        const { nodePubKey, nodeIndex } = authTokenData;
        const share = shares[new bn_js_1.default(nodeIndex).toString('hex', 64)];
        const shareJson = share.toJSON();
        return encryptData(Buffer.from(shareJson.share.padStart(64, '0'), 'hex'), Buffer.from(nodePubKey, 'hex'));
    });
    const encryptedShares = await Promise.all(encryptionPromises);
    // Create share import items
    return Promise.all(authTokens.map(async (tokenData, i) => {
        return createShareImportItem(encryptedShares[i], keyIndex, tokenData.authToken, Buffer.from(tokenData.nodePubKey, 'hex'), tokenData.nodeIndex, nodeEndpointsMap);
    }));
};
exports.generateShareImportItems = generateShareImportItems;
//# sourceMappingURL=utils.cjs.map