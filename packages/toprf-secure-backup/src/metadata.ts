import {
  SomeError,
  Some,
  safeStringify,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { gcm } from '@noble/ciphers/aes';
import { managedNonce } from '@noble/ciphers/webcrypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';

import type {
  FetchSecretDataResult,
  IGetSecretDataRequestBody,
  KeyPair,
  AddSecretDataItemParams,
  NodeAuthTokens,
  ISetSecretDataRequestBody,
} from './interfaces';

type MetadataStoreOptions = {
  nodeEndpointsMap: Map<number, string>;
};

export type AuthTokenToMetadataEndpointsMap = Record<string, string>;

/**
 * Error class for metadata store.
 */
export class MetadataStoreError extends Error {
  /**
   * Constructor for MetadataStoreError.
   *
   * @param message - The error message.
   */
  constructor(message: string) {
    super(message);
    this.name = 'MetadataStoreError';
    Object.setPrototypeOf(this, MetadataStoreError.prototype);
  }
}

/**
 * MetadataStore class.
 *
 * This class is used to store and retrieve encrypted account metadata for the
 * given feature.
 */
export class MetadataStore {
  readonly #feature = 'srp-backup';

  readonly #nodeEndpointsMap: Map<number, string>;

  readonly #thresholdValues: { [operation: string]: number } = {
    /**
     * Minimum number of nodes required to satisfy the threshold check for adding secret data.
     */
    addSecretDataItem: 4,
    /**
     * Minimum number of nodes required to satisfy the threshold check for fetching all secret data items.
     */
    fetchAllSecretDataItems: 3,
  };

  /**
   *
   * @param options - The initialization options for the metadata store.
   * @param options.nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
   * @param options.storageLocation - The storage location of the metadata.
   */
  constructor(options: MetadataStoreOptions) {
    this.#nodeEndpointsMap = options.nodeEndpointsMap;
  }

  /**
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.nodeAuthTokens - The array of auth tokens to be used for authenticating against the metadata server.
   * @returns A promise that resolves when the secret data is stored.
   */
  async addSecretDataItem(params: AddSecretDataItemParams): Promise<void> {
    try {
      const { secretData, encKey, nodeAuthTokens, authKeyPair } = params;
      const endPointToAuthTokenMap =
        this.#getAuthTokenToMetadataEndpointsMap(nodeAuthTokens);

      const promises = Object.entries(endPointToAuthTokenMap).map(
        async ([endpoint, authToken]) => {
          return this.#addData({
            secretData,
            encKey,
            authKeyPair,
            metadataEndpoint: endpoint,
            authToken,
          });
        },
      );
      const thresholdCount = this.#thresholdValues.addSecretDataItem;
      await this.#thresholdCheck<boolean>(promises, thresholdCount);
    } catch (error) {
      if (error instanceof SomeError) {
        throw new MetadataStoreError(
          `failed to store metadata: ${error.predicate}`,
        );
      }
      throw new MetadataStoreError(
        `failed to store metadata: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Fetches the secret data from the metadata store and decrypts it.
   *
   * @param encKey - The encryption key to be used for decrypting the secret data.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async fetchAllSecretDataItems(
    encKey: Uint8Array,
    authKeyPair: KeyPair,
  ): Promise<FetchSecretDataResult> {
    try {
      const promises = Array.from(this.#nodeEndpointsMap.values()).map(
        async (metadataEndpoint) => {
          return this.#getAllDataItems({
            encKey,
            authKeyPair,
            metadataEndpoint,
          });
        },
      );
      const thresholdCount = this.#thresholdValues.fetchAllSecretDataItems;
      const thresholdResult = await this.#thresholdReadSecretData(
        promises,
        thresholdCount,
      );

      return thresholdResult;
    } catch (error) {
      if (error instanceof SomeError) {
        throw new MetadataStoreError(
          `failed to fetch metadata: ${error.predicate}`,
        );
      }
      throw new MetadataStoreError(
        `failed to fetch metadata: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Encrypts the secret data and inserts or appends it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for storing the secret data.
   * @param params.authToken - The auth token to be used for authentication for the metadata server.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #addData(params: {
    secretData: Uint8Array;
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
    authToken: string;
  }): Promise<boolean> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/set`;
      const encryptedData = this.#encryptData(params.secretData, params.encKey);
      const payload = this.#generatePayloadForSetOrBatchSet(
        encryptedData,
        params.authKeyPair,
        // params.authToken,
      );

      const requestBody = JSON.stringify(payload);
      console.log('requestBody', requestBody);
      const response = await fetch(url, {
        headers: {
          // eslint-disable-next-line @typescript-eslint/naming-convention
          'Content-Type': 'application/json',
        },
        method: 'POST',
        body: requestBody,
      });

      if (!response.ok) {
        const responseBody = await response.json();
        throw new Error(`HTTP error message: ${responseBody.error}`);
      }
      const jsonData = await response.json();
      return jsonData.success;
    } catch (error: unknown) {
      const errorMessage = (error as Error).message || 'Unknown error';
      throw new MetadataStoreError(
        `failed to upsert metadata: ${errorMessage}`,
      );
    }
  }

  /**
   * Fetches all the secret data from the metadata store by provided public key and decrypts it.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.encKey - The encryption key to be used for decrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for fetching the secret data.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async #getAllDataItems(params: {
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
  }): Promise<Uint8Array[]> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/get`;
      const payload = this.#generatePayloadForGetSecretDataRequest(
        params.authKeyPair,
      );

      const response = await fetch(url, {
        headers: {
          // eslint-disable-next-line @typescript-eslint/naming-convention
          'Content-Type': 'application/json',
        },
        method: 'POST',
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const responseBody = await response.json();
        throw new Error(`HTTP error message: ${responseBody.error}`);
      }

      const jsonData = await response.json();
      if (!jsonData) {
        throw new MetadataStoreError('Empty response from metadata server');
      }

      if ('error' in jsonData) {
        throw new MetadataStoreError(`Server error: ${jsonData.error}`);
      }

      if (!jsonData.data) {
        // This could mean no data exists yet.
        return [];
      }

      if (!Array.isArray(jsonData.data)) {
        throw new MetadataStoreError('Invalid data format: expected array');
      }

      const secretData = jsonData.data.map((data: string) => {
        const rawData = new Uint8Array(Buffer.from(data, 'base64'));
        return this.#decryptData(rawData, params.encKey);
      });
      return secretData;
    } catch (error) {
      console.log('error while fetching metadata', error);
      const errorMessage = (error as Error).message || 'Unknown error';
      throw new MetadataStoreError(`failed to fetch metadata: ${errorMessage}`);
    }
  }

  /**
   * Validates Metadata Responses with threshold check.
   *
   * Criteria to be met:
   * Out of n results, t items must share the same value.
   *
   * @param promises - The array of promises to be validated.
   * @param thresholdCount - The threshold value to be used for the threshold check.
   * @returns The validated result which satisfies the threshold check.
   */
  async #thresholdCheck<DataType>(
    promises: Promise<DataType>[],
    thresholdCount: number,
  ): Promise<DataType | null> {
    const results = await Some<DataType, DataType>(
      promises,
      async (resultArray: DataType[]) => {
        const tResult = thresholdSame(resultArray, thresholdCount);
        if (tResult) {
          return Promise.resolve(tResult);
        }

        return Promise.reject(new MetadataStoreError('Threshold not resolved'));
      },
    );

    return results ?? null;
  }

  /**
   * Processes an array of promises that resolve to byte arrays and finds threshold-matching values.
   *
   * @description
   * This function:
   * 1. Waits for promises to resolve into arrays of Uint8Array
   * 2. Counts occurrences of unique values across all arrays
   * 3. Returns values that appear at least `thresholdCount` times
   *
   * @param promises - Array of promises that resolve to arrays of Uint8Array
   * @param thresholdCount - Minimum number of occurrences required for a value to be included
   *
   * @returns Promise that resolves to:
   * - Array of Uint8Array values that meet the threshold requirement
   * - It returns as soon as it finds the threshold-matching values.
   * - It keeps on checking all the nodes until it finds the threshold-matching values for all the items.
   *
   * @example
   *const data = [[1, 2, 3], [1, 2], [1, 2], [1, 3], [1, 3]];
   *const threshold = 3;
   *const result = await #thresholdReadSecretData(data, threshold);
   *console.log(result); // [1, 2, 3]
   */
  async #thresholdReadSecretData(
    promises: Promise<Uint8Array[]>[],
    thresholdCount: number,
  ): Promise<Uint8Array[]> {
    return Some<Uint8Array[], Uint8Array[]>(
      promises,
      async (resultArray: Uint8Array[][], error?: Error[]) => {
        const count: Record<string, number> = {};
        const allItems = new Set<string>();
        // First pass: collect all unique items
        for (const nodeData of resultArray) {
          if (!nodeData) {
            continue;
          }
          for (const item of nodeData) {
            allItems.add(bytesToHex(item));
          }
        }

        // Second pass: count occurrences
        for (const nodeData of resultArray) {
          if (!nodeData) {
            continue;
          }
          const unique = new Set([...nodeData]);
          for (const item of unique) {
            const hexItem = bytesToHex(item);
            count[hexItem] = (count[hexItem] || 0) + 1;
          }
        }

        // Only return result when we've checked all nodes or found threshold matches for all items
        const thresholdMatches = Object.keys(count)
          .filter((item) => count[item] >= thresholdCount)
          .map((item) => hexToBytes(item));

        // If we've found all items meeting threshold already, return the result
        if (thresholdMatches.length === allItems.size) {
          return thresholdMatches;
        }

        // if we have checked all the nodes and no error found return thresholdMatches
        if (
          resultArray.length + (error?.length ?? 0) >= promises.length &&
          !(error?.length ?? 0)
        ) {
          return thresholdMatches;
        }
        // throw and wait for result from other nodes.
        throw new MetadataStoreError('Unable to resolve threshold for data');
      },
    );
  }

  /**
   * Generate the payload for the set or batch set secret data request and get payload signature.
   *
   * @param rawData - The encrypted secret data to be stored.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
  //  * @param authToken - The auth token to be used for authentication for the metadata server.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSet(
    rawData: Uint8Array,
    authKeyPair: KeyPair,
    // authToken: string,
  ): ISetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const base64Data = Buffer.from(rawData).toString('base64');

    const { pk, sk } = authKeyPair;
    const signature = this.#generatePayloadSignature(
      { data: base64Data, timestamp, feature },
      sk,
    );

    const pubKey = bytesToHex(pk);

    return {
      data: base64Data,
      signature,
      feature,
      timestamp,
      // authToken,
      pubKey,
    };
  }

  /**
   * Generate the payload for the get secret data request and get payload signature.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns The payload for the get secret data request.
   */
  #generatePayloadForGetSecretDataRequest(
    authKeyPair: KeyPair,
  ): IGetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const { pk, sk } = authKeyPair;

    const signature = this.#generatePayloadSignature(
      { feature, timestamp },
      sk,
    );

    const pubKey = bytesToHex(pk);

    return {
      feature,
      pubKey,
      timestamp,
      signature,
    };
  }

  /**
   * Generate the signature for the payload.
   *
   * @param payload - The payload to be signed.
   * @param privKey - The private key to sign the payload.
   * @returns The signature hex string.
   */
  #generatePayloadSignature(
    payload: Record<string, unknown>,
    privKey: bigint,
  ): string {
    const payloadString = safeStringify(payload);
    const hash = keccak256(payloadString);
    const signature = secp256k1.sign(hash, privKey);

    return signature.toCompactHex();
  }

  /**
   * Get the auth token to metadata endpoints map.
   *
   * @param nodeAuthTokens - The node auth tokens.
   * @returns The auth token to metadata endpoints map.
   */
  #getAuthTokenToMetadataEndpointsMap(
    nodeAuthTokens: NodeAuthTokens,
  ): AuthTokenToMetadataEndpointsMap {
    const endPointToAuthTokenMap: AuthTokenToMetadataEndpointsMap = {};
    nodeAuthTokens.forEach(({ nodeIndex, authToken }) => {
      const endpoint = this.#nodeEndpointsMap.get(nodeIndex);
      if (!endpoint) {
        throw new MetadataStoreError(
          `Endpoint not found for node index: ${nodeIndex}`,
        );
      }

      endPointToAuthTokenMap[endpoint] = authToken;
    });

    return endPointToAuthTokenMap;
  }

  /**
   * Encrypt the data using the key with AES-256-GCM.
   *
   * @param data - The secret data to be encrypted.
   * @param encryptionKey - The encryption key to encrypt the data.
   * @returns The encrypted data.
   */
  #encryptData(data: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
    const aesGcm = managedNonce(gcm)(encryptionKey);
    const ciphertext = aesGcm.encrypt(data);
    return ciphertext;
  }

  /**
   * Decrypt the data using the encryption key.
   *
   * @param cipherText - The cipher text, encrypted with AES-256-GCM.
   * @param decryptionKey - The encryption key to decrypt the data.
   * @returns The decrypted data.
   */
  #decryptData(cipherText: Uint8Array, decryptionKey: Uint8Array): Uint8Array {
    const aesGcm = managedNonce(gcm)(decryptionKey);
    const decryptedData = aesGcm.decrypt(cipherText);

    return decryptedData;
  }
}
