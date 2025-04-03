import {
  SomeError,
  Some,
  safeStringify,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { gcm } from '@noble/ciphers/aes';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { bytesToHex, concatBytes, randomBytes } from '@noble/hashes/utils';

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

  // Nonce size for AES-256-GCM
  readonly #nonceSize = 24;

  readonly #nodeEndpointsMap: Map<number, string>;

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
      const thresholdCount =
        Math.floor(Object.keys(endPointToAuthTokenMap).length / 2) + 1;
      await this.#thresholdCheck<boolean>(promises, thresholdCount);
    } catch (error) {
      if (error instanceof SomeError) {
        throw new MetadataStoreError(
          `failed to store metadata: ${error.predicate}`,
        );
      }
      throw new MetadataStoreError(
        `failed to fetch metadata: ${(error as Error).message}`,
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
      const thresholdCount = Math.floor(this.#nodeEndpointsMap.size / 2) + 1;
      const thresholdResult = await this.#thresholdCheck<Uint8Array[]>(
        promises,
        thresholdCount,
      );
      if (thresholdResult?.length === 0 || !thresholdResult) {
        return null;
      }

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
      const payload = this.#generatePayloadForSetOrBatchSetSecretDataRequest(
        encryptedData,
        params.authKeyPair,
        params.authToken,
      );

      const requestBody = JSON.stringify(payload);

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
      if (!jsonData.data) {
        throw new MetadataStoreError('Failed to fetch metadata');
      }

      const secretData = jsonData.data.map((data: string) =>
        this.#decryptData(data, params.encKey),
      );
      return secretData;
    } catch (error) {
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
  async #thresholdCheck<T>(
    promises: Promise<T>[],
    thresholdCount: number,
  ): Promise<T | null> {
    const results = await Some<T, T>(promises, async (resultArray) => {
      const tResult = thresholdSame(resultArray, thresholdCount);
      if (tResult) {
        return Promise.resolve(tResult);
      }

      return Promise.reject(new MetadataStoreError('Threshold not resolved'));
    });

    return results ?? null;
  }

  /**
   * Generate the payload for the set or batch set secret data request and get payload signature.
   *
   * @param rawData - The encrypted secret data to be stored.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param authToken - The auth token to be used for authentication for the metadata server.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSetSecretDataRequest(
    rawData: Uint8Array,
    authKeyPair: KeyPair,
    authToken: string,
  ): ISetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const base64Data = Buffer.from(rawData).toString('base64');

    const { pubKey: pubKeyRaw, privKey } = authKeyPair;
    const signature = this.#generatePayloadSignature(
      { data: base64Data, timestamp, feature, authToken },
      privKey,
    );

    const pubKey = bytesToHex(pubKeyRaw);

    return {
      data: base64Data,
      signature,
      feature,
      timestamp,
      authToken,
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
    const { pubKey: pubKeyRaw, privKey } = authKeyPair;

    const signature = this.#generatePayloadSignature(
      { feature, timestamp },
      privKey,
    );

    const pubKey = bytesToHex(pubKeyRaw);

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
   * Derive AES-256 key from seed and encrypt the data using the key.
   *
   * We might not need it if we're using Profile-Sync SDK since encryption is handled in the SDK
   *
   * @param data - The secret data to be encrypted.
   * @param encryptionKey - The encryption key to encrypt the data.
   * @returns The encrypted data.
   */
  #encryptData(data: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
    const nonce = randomBytes(this.#nonceSize);

    const aes = gcm(encryptionKey, nonce);
    const ciphertext = aes.encrypt(data);

    const cipherTextCombinedWithNonce = concatBytes(nonce, ciphertext);

    return cipherTextCombinedWithNonce;
  }

  /**
   * Decrypt the data using the encryption key.
   *
   * @param cipherTextCombinedWithNonceString - The cipher text combined with nonce.
   * @param encryptionKey - The encryption key to decrypt the data.
   * @returns The decrypted data.
   */
  #decryptData(
    cipherTextCombinedWithNonceString: string,
    encryptionKey: Uint8Array,
  ): Uint8Array {
    const cipherTextCombinedWithNonce = new Uint8Array(
      Buffer.from(cipherTextCombinedWithNonceString, 'base64'),
    );
    const nonce = cipherTextCombinedWithNonce.slice(0, this.#nonceSize);
    const rawEncData = cipherTextCombinedWithNonce.slice(this.#nonceSize);

    const aes = gcm(encryptionKey, nonce);
    const decryptedData = aes.decrypt(rawEncData);

    return decryptedData;
  }
}
