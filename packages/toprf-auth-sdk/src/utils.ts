import {
  encryptedParamsBufToHex,
  generateRandomPolynomial,
  getSecp256K1Curve,
} from '@metamask/auth-network-utils';
import type { INodePub } from '@toruslabs/constants';
import type { Ecies } from '@toruslabs/eccrypto';
import { encrypt } from '@toruslabs/eccrypto';
import BN from 'bn.js';
import type * as ec from 'elliptic';

import { NODE_URLS } from './constants';
import type { ShareImportItem } from './jrpcInterfaces';

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
) => {
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
 * @param share - The share to be used for the encryption.
 *
 * @returns The encrypted share, encrypted with the given node's public key.
 */
const encryptShareForNode = async (
  ecCurve: ec.ec,
  nodePubKey: INodePub,
  share: string,
): Promise<Ecies> => {
  const nodeKey = ecCurve.keyFromPublic({ x: nodePubKey.X, y: nodePubKey.Y });
  const shareBuffer = Buffer.from(share.padStart(64, '0'), 'hex');
  const pubKeyBuffer = Buffer.from(
    nodeKey.getPublic().encodeCompressed('hex'),
    'hex',
  );

  return encrypt(pubKeyBuffer, shareBuffer);
};

/**
 * Creates a share import item for a node
 *
 * @param encryptedShare - The encrypted share to be used for the share import item.
 * @param keyIndex - The key index to be used for the share import item.
 * @param nodeIndex - The node index to be used for the share import item.
 *
 * @returns The share import item containing the encrypted share, the key index, the node index, and the sss endpoint.
 */
const createShareImportItem = (
  encryptedShare: Ecies,
  keyIndex: number,
  nodeIndex: number,
): ShareImportItem => {
  const encParamsMetadata = encryptedParamsBufToHex(encryptedShare);

  return {
    encrypted_share: encParamsMetadata.ciphertext,
    encrypted_share_metadata: encParamsMetadata,
    share_key_index: keyIndex,
    node_index: nodeIndex,
    sss_endpoint: NODE_URLS[nodeIndex - 1],
  };
};

/**
 * Generates encrypted share import items for each node
 *
 * @param nodeIndexes - The node indexes to be used for the share import items.
 * @param nodePubkeys - The node public keys to be used for the share import items.
 * @param privKey - The private key to be used for the share import items.
 * @param keyIndex - The key index to be used for the share import items.
 *
 * @returns The share import items containing the encrypted shares, the key index, the node index, and the sss endpoint.
 */
export const generateShareImportItems = async (
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  privKey: BN,
  keyIndex: number,
): Promise<ShareImportItem[]> => {
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
    return encryptShareForNode(ecCurve, nodePubkeys[i], shareJson.share);
  });

  const encryptedShares = await Promise.all(encryptionPromises);

  // Create share import items
  return nodeIndexes.map((nodeIndex, i) =>
    createShareImportItem(encryptedShares[i], keyIndex, nodeIndex),
  );
};
