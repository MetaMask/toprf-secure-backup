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
import type { INodePub } from '@toruslabs/constants';
import { decrypt, encrypt } from '@toruslabs/eccrypto';
import { post } from '@toruslabs/http-helpers';
import BN from 'bn.js';
import type * as ec from 'elliptic';

import { NODE_URLS } from './constants';
import type { NodeAuthToken } from './interfaces';
import type { ShareImportItem } from './jrpcInterfaces';

type EncryptedData = {
  data: string;
  metadata: Omit<EciesHex, 'ciphertext'>;
};

/**
 * Randomly selects a node URL from the available nodes
 *
 * @returns An object containing:
 * - url: The URL of the randomly selected node
 * - index: The 1-based index of the selected node
 */
export const getRandomNode = (): { url: string; index: string } => {
  const randomIndex = Math.floor(Math.random() * NODE_URLS.length);
  return {
    url: NODE_URLS[randomIndex],
    index: String(randomIndex + 1),
  };
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
  ecCurve: ec.ec,
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
 * Encrypts a share for a node using its public key
 *
 * @param ecCurve - The elliptic curve to be used for the encryption.
 * @param nodePubKey - The public key of the node to be used for the encryption.
 * @param data - The buffer data to be used for the encryption.
 *
 * @returns The encrypted data, encrypted with the given node's public key.
 */
const encryptDataForNode = async (
  ecCurve: ec.ec,
  nodePubKey: INodePub,
  data: Buffer,
): Promise<EncryptedData> => {
  const nodeKey = ecCurve.keyFromPublic({ x: nodePubKey.X, y: nodePubKey.Y });
  const pubKeyBuffer = Buffer.from(
    nodeKey.getPublic().encodeCompressed('hex'),
    'hex',
  );

  const encryptedData = await encrypt(pubKeyBuffer, data);
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
 * @param authToken - The auth token of the node required for validating the user on backend.
 * @param keyIndex - The key index to be used for the share import item.
 * @param nodePubKey - The public key of the node to be used for the share import item.
 * @param nodeIndex - The node index to be used for the share import item.
 *
 * @returns The share import item containing the encrypted share, the key index, the node index, and the sss endpoint.
 */
const createShareImportItem = async (
  encryptedShare: EncryptedData,
  authToken: string,
  keyIndex: number,
  nodePubKey: INodePub,
  nodeIndex: number,
): Promise<ShareImportItem> => {
  const ecCurve = getSecp256K1Curve();
  const encryptedAuthToken = await encryptDataForNode(
    ecCurve,
    nodePubKey,
    Buffer.from(authToken, 'base64'),
  );

  return {
    encryptedShare: JSON.stringify(encryptedShare),
    encryptedAuthToken: JSON.stringify(encryptedAuthToken),
    shareKeyIndex: keyIndex,
    nodeIndex,
    sssEndpoint: NODE_URLS[nodeIndex - 1],
  };
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
export const generateShareImportItems = async (
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  authTokens: NodeAuthToken[],
  privKey: BN,
  keyIndex: number,
): Promise<ShareImportItem[]> => {
  if (
    nodeIndexes.length !== nodePubkeys.length ||
    nodeIndexes.length !== authTokens.length
  ) {
    throw new Error(
      'Invalid inputs, nodeIndexes, nodePubkeys and authTokens must have the same length while generating share import items',
    );
  }
  const ecCurve = getSecp256K1Curve();
  const threshold = Math.floor(nodePubkeys.length / 2) + 1;

  // Generate shares for each node
  const shares = generateShares(ecCurve, nodeIndexes, privKey, threshold);

  // Encrypt shares for each node
  const encryptionPromises = nodeIndexes.map(async (nodeIndex, i) => {
    if (!nodePubkeys[i]) {
      throw new Error(`Missing node pub key for node index: ${nodeIndex}`);
    }

    const shareJson = shares[
      new BN(nodeIndex).toString('hex', 64)
    ].toJSON() as Record<string, string>;
    return encryptDataForNode(
      ecCurve,
      nodePubkeys[i],
      Buffer.from(shareJson.share.padStart(64, '0'), 'hex'),
    );
  });

  const encryptedShares = await Promise.all(encryptionPromises);

  const authTokensMap = new Map<number, NodeAuthToken>();
  authTokens.forEach((token) => {
    authTokensMap.set(token.nodeIndex, token);
  });

  // Create share import items
  return Promise.all(
    authTokens.map(async (tokenData, i) =>
      createShareImportItem(
        encryptedShares[i],
        tokenData.authToken,
        keyIndex,
        nodePubkeys[tokenData.nodeIndex - 1],
        tokenData.nodeIndex,
      ),
    ),
  );
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
    result?: JSONValue;
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
  sessionPrivateKey: string,
): Promise<string> => {
  const ecCurve = getSecp256K1Curve();
  const decryptionKey = ecCurve.keyFromPrivate(sessionPrivateKey);
  const authTokenData = JSON.parse(authToken) as EncryptedData;
  const metadata = encParamsHexToBuf(authTokenData.metadata);

  const decryptedAuthToken = await decrypt(
    decryptionKey.getPrivate().toArrayLike(Buffer),
    {
      ...metadata,
      ciphertext: Buffer.from(authTokenData.data, 'hex'),
    },
  );
  return Buffer.from(decryptedAuthToken).toString('base64');
};
