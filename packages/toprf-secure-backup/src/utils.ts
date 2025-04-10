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
import { secp256k1 as secp256k1Noble } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { decrypt, encrypt } from '@toruslabs/eccrypto';
import { post } from '@toruslabs/http-helpers';
import BN from 'bn.js';
import type * as EC from 'elliptic';

import { GENERATE_SHARE_THRESHOLD } from './constants';
import type { KeyChangeProof, NodeAuthTokens } from './interfaces';
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
    id: number;
    jsonrpc: '2.0';
    result?: JSONValue | undefined;
    error?: {
      code: number;
      message: string;
      data?: unknown;
    };
  },
>(
  endpoint: string,
  request: JRPCRequest<JSONValue>,
): Promise<Response> => {
  const req = { ...request };
  req.params = toSnakeCaseKeys(request.params);

  return post<Response>(endpoint, req, {}, { logTracingHeader: false })
    .then((res) => {
      if (res.result) {
        res.result = toCamelCaseKeys(res.result);
      }
      return res;
    })
    .catch((er: unknown) => {
      return {
        id: request.id,
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Internal error',
          data: er,
        },
      } as Response;
    });
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
 * Prepares shares for the given nodes, calculating threshold and converting parameters
 *
 * @param nodeEndpointsMap - Map of node indexes to endpoints
 * @param privKey - Private key to use for shares
 * @returns The prepared shares and node indexes
 */
export const prepareNodeShares = (
  nodeEndpointsMap: Record<number, string>,
  privKey: bigint,
): { shares: ShareMap; nodeIndexes: number[] } => {
  const privKeyBN = bigIntToBN(privKey);
  const ecCurve = getSecp256K1Curve();
  const allNodeIndexes = Object.keys(nodeEndpointsMap).map((val: string) =>
    parseInt(val, 10),
  );
  const threshold = GENERATE_SHARE_THRESHOLD;
  const shares = generateShares(ecCurve, allNodeIndexes, privKeyBN, threshold);

  return { shares, nodeIndexes: allNodeIndexes };
};

/**
 * Formats a share value into a 32-byte buffer with padding and base64 encoding
 *
 * @param shareValue - BN share value to format
 * @returns Base64 string of padded share
 */
const formatShareForSigning = (shareValue: BN): string => {
  // Convert to padded 32-byte buffer with value right-aligned
  const buffer = shareValue.toArrayLike(Buffer, 'be', 32);

  // Convert to base64
  return buffer.toString('base64');
};

/**
 * Creates an Ethereum format signature (r+s+v)
 *
 * @param dataHash - Hash to sign
 * @param privateKeyBigInt - Private key as bigint
 * @returns Signature as r+s+v hex string
 */
const createEthereumSignature = (
  dataHash: Uint8Array,
  privateKeyBigInt: bigint,
): string => {
  const privateKeyHex = privateKeyBigInt.toString(16).padStart(64, '0');
  const signResult = secp256k1Noble.sign(dataHash, privateKeyHex);

  const signature = signResult.toCompactHex();
  const recV = (signResult.recovery + 27).toString(16).padStart(2, '0');

  return signature + recV;
};

/**
 * Creates a signature for key change using the share and old private key
 *
 * @param shareValue - Raw share value to sign
 * @param shareKeyIndex - Key index for the share
 * @param nodeIndex - Node index
 * @param oldAuthPrivKey - Old auth private key for signing
 * @returns The signature and timestamp as KeyChangeProof
 */
export const createKeyChangeProof = (
  shareValue: BN,
  shareKeyIndex: number,
  nodeIndex: number,
  oldAuthPrivKey: bigint,
): KeyChangeProof => {
  const timestamp = Math.floor(Date.now() / 1000);
  const shareBase64 = formatShareForSigning(shareValue);

  const dataToSign = toSnakeCaseKeys({
    shareData: shareBase64,
    shareKeyIndex,
    nodeIndex,
    timestamp,
  });

  const jsonData = JSON.stringify(dataToSign);
  const dataHash = keccak256(jsonData);
  const signature = createEthereumSignature(dataHash, oldAuthPrivKey);

  return {
    oldKeySignature: signature,
    signatureTimestamp: timestamp,
  };
};

/**
 * Generate standard share import items without key change proof
 *
 * @param shares - The raw shares generated for each node
 * @param nodeEndpointsMap - Map of node indexes to endpoints
 * @param authTokens - Auth tokens for each node
 * @param shareKeyIndex - Key index for the shares
 * @returns Share import items for standard flow
 */
export const createNewUserShareImportItems = async (
  shares: ShareMap,
  nodeEndpointsMap: Record<number, string>,
  authTokens: NodeAuthTokens,
  shareKeyIndex: number,
): Promise<ShareImportItem[]> => {
  return Promise.all(
    authTokens.map(async (tokenData) => {
      const { nodePubKey, nodeIndex, authToken } = tokenData;

      // Get the raw share for this node
      const shareKey = new BN(nodeIndex).toString('hex', 64);
      const share = shares[shareKey];
      const shareJson = share.toJSON() as Record<string, string>;

      // Encrypt the share
      const encryptedShare = await encryptData(
        Buffer.from(shareJson.share, 'hex'),
        Buffer.from(nodePubKey, 'hex'),
      );

      // Encrypt the auth token
      const encryptedAuthToken = await encryptData(
        Buffer.from(authToken, 'base64'),
        Buffer.from(nodePubKey, 'hex'),
      );

      // Return the standard share import item
      return {
        encryptedShare: JSON.stringify(encryptedShare),
        encryptedAuthToken: JSON.stringify(encryptedAuthToken),
        shareKeyIndex,
        nodeIndex,
        sssEndpoint: nodeEndpointsMap[nodeIndex],
      };
    }),
  );
};

/**
 * Generate key change share import items with proofs
 *
 * @param shares - The raw shares generated for each node
 * @param nodeEndpointsMap - Map of node indexes to endpoints
 * @param authTokens - Auth tokens for each node
 * @param shareKeyIndex - Key index for the shares
 * @param oldAuthPrivKey - Old private key for signing
 * @returns Share import items for key change flow
 */
export const createKeyChangeShareImportItems = async (
  shares: ShareMap,
  nodeEndpointsMap: Record<number, string>,
  authTokens: NodeAuthTokens,
  shareKeyIndex: number,
  oldAuthPrivKey: bigint,
): Promise<ShareImportItem<'keyChange'>[]> => {
  return Promise.all(
    authTokens.map(async (tokenData) => {
      const { nodePubKey, nodeIndex, authToken } = tokenData;

      // Get the raw share for this node
      const shareKey = new BN(nodeIndex).toString('hex', 64);
      const share = shares[shareKey];
      const shareJson = share.toJSON() as Record<string, string>;

      // Create key change proof
      const shareValue = new BN(shareJson.share, 16);
      const keyChangeProof = createKeyChangeProof(
        shareValue,
        shareKeyIndex,
        nodeIndex,
        oldAuthPrivKey,
      );

      // Encrypt the share
      const encryptedShare = await encryptData(
        Buffer.from(shareJson.share, 'hex'),
        Buffer.from(nodePubKey, 'hex'),
      );

      // Encrypt the auth token
      const encryptedAuthToken = await encryptData(
        Buffer.from(authToken, 'base64'),
        Buffer.from(nodePubKey, 'hex'),
      );

      // Return the key change share import item
      return {
        encryptedShare: JSON.stringify(encryptedShare),
        encryptedAuthToken: JSON.stringify(encryptedAuthToken),
        shareKeyIndex,
        nodeIndex,
        sssEndpoint: nodeEndpointsMap[nodeIndex],
        ...keyChangeProof,
      };
    }),
  );
};

/**
 * Generates encrypted share import items for each node
 *
 * @param nodeEndpointsMap - Map of node indexes to endpoints.
 * @param authTokens - The auth tokens issued by the nodes on authenticating the user.
 * @param privKey - The private key to be used for the share import items.
 * @param shareKeyIndex - The share key index to be used for the share import items.
 * @param args - Additional arguments based on ShareType.
 * When ShareType is 'keyChange', this must include the old auth private key for signing.
 *
 * @returns The share import items containing the encrypted shares. Will be type
 * ShareImportItem<'standard'> when using standard flow or
 * ShareImportItem<'keyChange'> when using key change flow.
 */
export const generateShareImportItems = async <
  ShareType extends 'standard' | 'keyChange' = 'standard',
>(
  nodeEndpointsMap: Record<number, string>,
  authTokens: NodeAuthTokens,
  privKey: bigint,
  shareKeyIndex: number,
  ...args: ShareType extends 'keyChange' ? [oldAuthPrivKey: bigint] : []
): Promise<ShareImportItem<ShareType>[]> => {
  // First prepare the shares for all nodes
  const { shares } = prepareNodeShares(nodeEndpointsMap, privKey);

  const oldAuthPrivKey = args[0];

  // Generate appropriate share import items based on whether it's a key change
  if (oldAuthPrivKey !== undefined) {
    return createKeyChangeShareImportItems(
      shares,
      nodeEndpointsMap,
      authTokens,
      shareKeyIndex,
      oldAuthPrivKey,
    ) as unknown as ShareImportItem<ShareType>[];
  }

  return createNewUserShareImportItems(
    shares,
    nodeEndpointsMap,
    authTokens,
    shareKeyIndex,
  ) as unknown as ShareImportItem<ShareType>[];
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
