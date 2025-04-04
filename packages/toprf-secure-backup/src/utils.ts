import type {
  EciesHex,
  JRPCRequest,
  JSONValue,
  ShareMap,
} from '@metamask/auth-network-utils';
import {
  encParamsHexToBuf,
  encryptedParamsBufToHex,
  generateRandomPolynomial,
  getSecp256K1Curve,
  toCamelCaseKeys,
  toSnakeCaseKeys,
} from '@metamask/auth-network-utils';
import { decrypt, encrypt } from '@toruslabs/eccrypto';
import { post } from '@toruslabs/http-helpers';
import BN from 'bn.js';
import type * as EC from 'elliptic';

import type { NodeAuthTokens } from './interfaces';
import type { ShareImportItem } from './jrpcInterfaces';

type EncryptedData = {
  data: string;
  metadata: Omit<EciesHex, 'ciphertext'>;
};

/**
 * Converts a BigInt to BN
 *
 * @param value - BigInt value to convert
 * @returns BN instance
 */
export const bigIntToBN = (value: bigint): BN => {
  return new BN(value.toString());
};

/**
 * Common post function that handles snake_case conversion of request params
 * and camelCase conversion of response result.
 *
 * @param endpoint - The endpoint to make the request to
 * @param request - The request object to send. The params are converted to snake_case.
 *
 * @returns The response with camelCase converted result
 */
export const postJRPCRequest = async <
  Response extends {
    result?: JSONValue | undefined;
  },
>(
  endpoint: string,
  request: JRPCRequest<JSONValue>,
): Promise<Response> => {
  const req = { ...request };
  const params = toSnakeCaseKeys(request.params);
  req.params = params;
  return post<Response>(endpoint, req, {}, { logTracingHeader: false }).then(
    (res) => {
      if (res.result) {
        res.result = toCamelCaseKeys(res.result);
      }
      return res;
    },
  );
};

/**
 * Decrypts the auth token using the session private key
 *
 * @param authToken - The auth token to be decrypted.
 * @param sessionPrivateKey - The session private key to be used for the decryption.
 *
 * @returns The decrypted auth token.
 */
export const decryptAuthToken = async (
  authToken: string,
  sessionPrivateKey: Uint8Array,
): Promise<string> => {
  const authTokenData = JSON.parse(authToken) as EncryptedData;
  const metadata = encParamsHexToBuf(authTokenData.metadata);

  const decryptedAuthToken = await decrypt(Buffer.from(sessionPrivateKey), {
    ...metadata,
    ciphertext: Buffer.from(authTokenData.data, 'hex'),
  });
  return Buffer.from(decryptedAuthToken).toString('base64');
};

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
const generateShares = (
  ecCurve: EC.ec,
  nodeIndexes: number[],
  privKey: BN,
  threshold: number,
): ShareMap => {
  const nodeIndexesBn = nodeIndexes.map((index) => new BN(index));
  const degree = threshold - 1;
  const poly = generateRandomPolynomial(ecCurve, degree, privKey);
  return poly.generateShares(nodeIndexesBn);
};

/**
 * Encrypts given data using pub key.
 *
 * @param data - Data to be encrypted in buffer format.
 * @param pubKey - Encryption pub key buffer.
 * @returns The encrypted data, encrypted with the given node's public key.
 */
const encryptData = async (
  data: Buffer,
  pubKey: Buffer,
): Promise<EncryptedData> => {
  const encryptedData = await encrypt(pubKey, data);
  const encryptedDataHex = encryptedParamsBufToHex(encryptedData);
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
const createShareImportItem = async (
  encryptedShare: EncryptedData,
  keyIndex: number,
  authToken: string,
  nodePubKey: Buffer,
  nodeIndex: number,
  nodeEndpointsMap: Record<number, string>,
): Promise<ShareImportItem> => {
  const encryptedAuthToken = await encryptData(
    Buffer.from(authToken, 'base64'),
    nodePubKey,
  );

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
export const generateShareImportItems = async (
  nodeEndpointsMap: Record<number, string>,
  authTokens: NodeAuthTokens,
  privKey: bigint,
  keyIndex: number,
): Promise<ShareImportItem[]> => {
  const privKeyBN = bigIntToBN(privKey);
  const ecCurve = getSecp256K1Curve();
  const threshold = Math.floor(Object.values(nodeEndpointsMap).length / 2) + 1;
  const allNodeIndexes = Object.keys(nodeEndpointsMap).map((val: string) =>
    parseInt(val, 10),
  );
  // Generate shares for each node
  const shares = generateShares(ecCurve, allNodeIndexes, privKeyBN, threshold);

  // Encrypt shares for each node
  const encryptionPromises = authTokens.map(async (authTokenData) => {
    const { nodePubKey, nodeIndex } = authTokenData;

    const share = shares[new BN(nodeIndex).toString('hex', 64)];

    const shareJson = share.toJSON() as Record<string, string>;
    return encryptData(
      Buffer.from(shareJson.share.padStart(64, '0'), 'hex'),
      Buffer.from(nodePubKey, 'hex'),
    );
  });

  const encryptedShares = await Promise.all(encryptionPromises);

  // Create share import items
  return Promise.all(
    authTokens.map(async (tokenData, i) => {
      return createShareImportItem(
        encryptedShares[i],
        keyIndex,
        tokenData.authToken,
        Buffer.from(tokenData.nodePubKey, 'hex'),
        tokenData.nodeIndex,
        nodeEndpointsMap,
      );
    }),
  );
};

/**
 * Creates a map of node indexes to endpoints
 *
 * @param nodeEndpoints - The endpoints of the nodes.
 * @param nodeIndexes - The indexes of the nodes.
 *
 * @returns A map of node indexes to endpoints.
 */
export const createNodeEndpointsMap = (
  nodeEndpoints: string[],
  nodeIndexes: number[],
): Record<number, string> => {
  return nodeIndexes.reduce<Record<number, string>>((acc, index) => {
    acc[index] = nodeEndpoints[index - 1];
    return acc;
  }, {});
};
