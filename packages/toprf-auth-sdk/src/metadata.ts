import {
  SomeError,
  Some,
  safeStringify,
  thresholdSame,
} from '@metamask/auth-network-utils';
import { gcm } from '@noble/ciphers/aes';
import { bytesToUtf8 } from '@noble/ciphers/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import {
  bytesToHex,
  concatBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils';

import type {
  FetchSecretDataResult,
  IGetSecretDataRequestBody,
  ISetSecretDataRequestBody,
  KeyPair,
  NodeAuthTokens,
} from './interfaces';

export enum MetadataStorageLocation {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  METADATA_SERVER = 'metadata-server',
  // TODO: add profile-sync storage location in the future
  // PROFILE_SYNC = 'profile-sync',
}

type MetadataStoreOptions = {
  authTokens: NodeAuthTokens;
  storageLocation?: MetadataStorageLocation;
  nodeEndpoints?: string[];
  nodeIndexes?: number[];
};

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

  readonly #storageLocation: MetadataStorageLocation;

  // Nonce size for AES-256-GCM
  readonly #nonceSize = 24;

  readonly #authTokens: NodeAuthTokens;

  readonly #metadataEndpoints: string[] = [];

  readonly #nodeIndexes: number[] = [];

  readonly #thresholdCount: number;

  /**
   *
   * @param options - The initialization options for the metadata store.
   * @param options.authTokens - The array of auth tokens to be used for authenticating requests to the metadata service.
   * @param options.storageLocation - The storage location of the metadata.
   * @param options.nodeEndpoints - The array of node endpoints to be used for authenticating requests to the metadata service.
   * @param options.nodeIndexes - The array of node indexes to be used for authenticating requests to the metadata service.
   */
  constructor({
    authTokens,
    nodeEndpoints,
    nodeIndexes,
    storageLocation = MetadataStorageLocation.METADATA_SERVER,
  }: MetadataStoreOptions) {
    this.#storageLocation = storageLocation;
    this.#authTokens = authTokens;

    if (!nodeEndpoints || !nodeIndexes) {
      throw new MetadataStoreError(
        'nodeEndpoints and nodeIndexes are required for metadata server',
      );
    }

    if (nodeEndpoints.length !== nodeIndexes.length) {
      throw new MetadataStoreError(
        'nodeEndpoints and nodeIndexes must have the same length',
      );
    }

    this.#metadataEndpoints = nodeEndpoints;
    this.#nodeIndexes = nodeIndexes;

    this.#thresholdCount = Math.floor(this.#metadataEndpoints.length / 2) + 1;
  }

  /**
   * Get the storage location of the metadata.
   *
   * @returns The storage location of the metadata.
   */
  get metadataStorageLocation(): MetadataStorageLocation {
    return this.#storageLocation;
  }

  /**
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param secretData - The secret data to be stored.
   * @param encKey - The encryption key to be used for encrypting the secret data.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async storeSecretData(
    secretData: string,
    encKey: Uint8Array,
    authKeyPair: KeyPair,
  ): Promise<void> {
    await Promise.all(
      // eslint-disable-next-line @typescript-eslint/promise-function-async
      this.#metadataEndpoints.map((endpoint, index) => {
        const nodeIndex = this.#nodeIndexes[index];
        return this.#setData({
          secretData,
          encKey,
          authKeyPair,
          metadataEndpoint: endpoint,
          nodeIndex,
        });
      }),
    );
  }

  /**
   * Fetches the secret data from the metadata store and decrypts it.
   *
   * @param encKey - The encryption key to be used for decrypting the secret data.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async fetchSecretData(
    encKey: Uint8Array,
    authKeyPair: KeyPair,
  ): Promise<FetchSecretDataResult | null> {
    try {
      const promises = this.#metadataEndpoints.map(
        async (metadataEndpoint, index) => {
          const nodeIndex = this.#nodeIndexes[index];
          return this.#getData({
            encKey,
            authKeyPair,
            nodeIndex,
            metadataEndpoint,
          });
        },
      );

      const thresholdResult = await this.#thresholdCheck(promises);
      if (thresholdResult?.length === 0 || !thresholdResult) {
        return null;
      }

      return { secretData: thresholdResult };
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
   * Encrypts the secret data and inserts or updates it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for storing the secret data.
   * @param params.nodeIndex - The index of the metadata server to be used for storing the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #setData(params: {
    secretData: string;
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
    nodeIndex: number;
  }): Promise<void> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/set`;
      const encryptedData = this.#encryptData(params.secretData, params.encKey);
      const payload = this.#generatePayloadForSetOrBatchSetSecretDataRequest(
        encryptedData,
        params.authKeyPair,
        params.nodeIndex,
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
    } catch (error: unknown) {
      const errorMessage = (error as Error).message || 'Unknown error';
      throw new MetadataStoreError(
        `failed to upsert metadata: ${errorMessage}`,
      );
    }
  }

  /**
   * Fetches the secret data from the metadata store by provided public key and decrypts it.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.encKey - The encryption key to be used for decrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.nodeIndex - The index of the Auth Token to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for fetching the secret data.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async #getData(params: {
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    nodeIndex: number;
    metadataEndpoint: string;
  }): Promise<string[]> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/get`;
      const payload = this.#generatePayloadForGetSecretDataRequest(
        params.authKeyPair,
        params.nodeIndex,
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
   * @returns The validated result which satisfies the threshold check.
   */
  async #thresholdCheck(
    promises: Promise<string[]>[],
  ): Promise<string[] | null> {
    const results = await Some<string[], string[]>(
      promises,
      async (resultArray) => {
        const tResult = thresholdSame(resultArray, this.#thresholdCount);
        if (tResult) {
          return Promise.resolve(tResult);
        }

        return Promise.reject(new MetadataStoreError('Threshold not resolved'));
      },
    );

    return results ?? null;
  }

  /**
   * Generate the payload for the set or batch set secret data request and get payload signature.
   *
   * @param data - The encrypted secret data to be stored.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param nodeIndex - The index of the Auth Token to be used for authenticating the secret data.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSetSecretDataRequest(
    data: string,
    authKeyPair: KeyPair,
    nodeIndex: number,
  ): ISetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const authToken = this.#getAuthToken(nodeIndex);

    const { pubKey: pubKeyRaw, privKey } = authKeyPair;
    const signature = this.#generatePayloadSignature(
      { data, timestamp, feature, authToken },
      privKey,
    );

    const pubKey = bytesToHex(pubKeyRaw);

    return {
      data,
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
   * @param nodeIndex - The index of the Auth Token to be used for authenticating the secret data.
   * @returns The payload for the get secret data request.
   */
  #generatePayloadForGetSecretDataRequest(
    authKeyPair: KeyPair,
    nodeIndex: number,
  ): IGetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const authToken = this.#getAuthToken(nodeIndex);
    const { pubKey: pubKeyRaw, privKey } = authKeyPair;

    const signature = this.#generatePayloadSignature(
      { feature, timestamp, authToken },
      privKey,
    );

    const pubKey = bytesToHex(pubKeyRaw);

    return {
      feature,
      pubKey,
      timestamp,
      authToken,
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
   * Get the auth token for the given node index.
   *
   * @param nodeIndex - The index of the Auth Token to be used for authenticating the secret data.
   * @returns The auth token.
   */
  #getAuthToken(nodeIndex: number): string {
    const authToken = this.#authTokens.find(
      (authTokenObj) => authTokenObj.nodeIndex === nodeIndex,
    );

    if (!authToken) {
      throw new MetadataStoreError(
        `Auth token not found for node index: ${nodeIndex}`,
      );
    }

    return authToken.authToken;
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
  #encryptData(data: string, encryptionKey: Uint8Array): string {
    const nonce = randomBytes(this.#nonceSize);
    const rawData = utf8ToBytes(data);

    const aes = gcm(encryptionKey, nonce);
    const ciphertext = aes.encrypt(rawData);

    const cipherTextCombinedWithNonce = concatBytes(nonce, ciphertext);

    return Buffer.from(cipherTextCombinedWithNonce).toString('base64');
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
  ): string {
    const cipherTextCombinedWithNonce = new Uint8Array(
      Buffer.from(cipherTextCombinedWithNonceString, 'base64'),
    );
    const nonce = cipherTextCombinedWithNonce.slice(0, this.#nonceSize);
    const rawEncData = cipherTextCombinedWithNonce.slice(this.#nonceSize);

    const aes = gcm(encryptionKey, nonce);
    const rawData = aes.decrypt(rawEncData);

    return bytesToUtf8(rawData);
  }
}
