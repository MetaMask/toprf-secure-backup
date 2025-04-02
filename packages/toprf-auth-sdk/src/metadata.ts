import { safeStringify } from '@metamask/auth-network-utils';
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
  IBatchSetData,
  IBatchSetSecretDataRequestBody,
  IGetSecretDataRequestBody,
  IMetadataLockRequestBody,
  ISetSecretDataRequestBody,
  KeyPair,
  NodeAuthTokens,
} from './interfaces';

export enum MetadataStorageLocation {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  METADATA_SERVER = 'metadata-server',
  // eslint-disable-next-line @typescript-eslint/naming-convention
  PROFILE_SYNC = 'profile-sync',
}

export type MetadataLock = {
  id: string;
  nodeIndex: number;
}[];

export enum MetadataLockStatus {
  FAILED = 0,
  SUCCESS = 1,
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

    if (storageLocation === MetadataStorageLocation.METADATA_SERVER) {
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

      const metadataEndpoints = nodeEndpoints;

      this.#metadataEndpoints = metadataEndpoints;
      this.#nodeIndexes = nodeIndexes;
    } else {
      // Otherwise, the Profile-Sync SDK will handle the storage url
    }
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
    // TODO: add threshold check in the new PR
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
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param secretData - The array of secret data to be stored.
   * @param encKey - The encryption key to be used for encrypting the secret data.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async storeSecretDataBatch(
    secretData: string[],
    encKey: Uint8Array,
    authKeyPair: KeyPair,
  ): Promise<void> {
    await Promise.all(
      // eslint-disable-next-line @typescript-eslint/promise-function-async
      this.#metadataEndpoints.map((metadataEndpoint, index) => {
        const nodeIndex = this.#nodeIndexes[index];
        return this.#batchSetData({
          secretData,
          encKey,
          authKeyPair,
          metadataEndpoint,
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
    // TODO: add threshold check in the new PR

    const results = await Promise.all(
      // eslint-disable-next-line @typescript-eslint/promise-function-async
      this.#metadataEndpoints.map((metadataEndpoint, index) => {
        const nodeIndex = this.#nodeIndexes[index];
        return this.#getData({
          encKey,
          authKeyPair,
          nodeIndex,
          metadataEndpoint,
        });
      }),
    );

    return results[0];
  }

  /**
   * Acquires a lock on the metadata store.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves with the lock id.
   */
  async acquireMetadataLock(authKeyPair: KeyPair): Promise<MetadataLock> {
    const lockResult = await Promise.all(
      // eslint-disable-next-line @typescript-eslint/promise-function-async
      this.#metadataEndpoints.map((metadataEndpoint) => {
        return this.#acquireLock(metadataEndpoint, authKeyPair);
      }),
    );

    const allLockAcquired = lockResult.every(
      (result) => result.status === MetadataLockStatus.SUCCESS,
    );

    if (!allLockAcquired) {
      throw new MetadataStoreError('Failed to acquire metadata lock');
    }

    const lock: MetadataLock = lockResult.map((result, idx) => {
      if (!result.id) {
        throw new MetadataStoreError(
          'Failed to acquire metadata lock. Missing lock id',
        );
      }

      return {
        id: result.id,
        nodeIndex: this.#nodeIndexes[idx],
      };
    });

    return lock;
  }

  /**
   * Releases the lock on the metadata store.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param metadataLock - The lock to be released.
   * @returns A promise that resolves with the lock status.
   */
  async releaseMetadataLock(
    authKeyPair: KeyPair,
    metadataLock: MetadataLock,
  ): Promise<MetadataLockStatus> {
    await Promise.all(
      // eslint-disable-next-line @typescript-eslint/promise-function-async
      this.#metadataEndpoints.map((metadataEndpoint, index) => {
        const nodeIndex = this.#nodeIndexes[index];
        const lockId = metadataLock.find(
          (lock) => lock.nodeIndex === nodeIndex,
        )?.id;
        if (!lockId) {
          throw new MetadataStoreError('Failed to release metadata lock');
        }
        return this.#releaseLock(metadataEndpoint, authKeyPair, lockId);
      }),
    );

    return MetadataLockStatus.SUCCESS;
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
      const payload =
        this.#generatePayloadForSetOrBatchSetSecretDataRequest<string>(
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
   * Encrypts the array of secret data and inserts them in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The array of secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for storing the secret data.
   * @param params.nodeIndex - The index of the metadata server to be used for storing the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #batchSetData(params: {
    secretData: string[];
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
    nodeIndex: number;
  }): Promise<void> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/batch_set`;
      const encryptedDataArray = params.secretData.map((secret) => ({
        data: this.#encryptData(secret, params.encKey),
      }));

      const payload =
        this.#generatePayloadForSetOrBatchSetSecretDataRequest<IBatchSetData>(
          encryptedDataArray,
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
  }): Promise<FetchSecretDataResult | null> {
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
        return null;
      }

      const secretData = jsonData.data.map((data: string) =>
        this.#decryptData(data, params.encKey),
      );
      return {
        secretData,
      };
    } catch (error) {
      const errorMessage = (error as Error).message || 'Unknown error';
      throw new MetadataStoreError(`failed to fetch metadata: ${errorMessage}`);
    }
  }

  /**
   * Acquires a lock on the metadata store.
   *
   * @param metadataEndpoint - The metadata server endpoint to be used for acquiring the lock.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves when the lock is acquired.
   */
  async #acquireLock(
    metadataEndpoint: string,
    authKeyPair: KeyPair,
  ): Promise<{ status: MetadataLockStatus; id?: string }> {
    try {
      const payload = this.#generatePayloadForLockRequests(authKeyPair);
      const url = `${metadataEndpoint}/acquireLock`;

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
      return {
        status: jsonData.status,
        id: jsonData.id,
      };
    } catch (error) {
      const errorMessage = (error as Error).message || 'Unknown error';
      throw new MetadataStoreError(
        `failed to acquire metadata lock: ${errorMessage}`,
      );
    }
  }

  /**
   * Releases the lock on the metadata store.
   *
   * @param metadataEndpoint - The metadata server endpoint to be used for releasing the lock.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param lockId - The lock id to be released.
   * @returns A promise that resolves with the lock status.
   */
  async #releaseLock(
    metadataEndpoint: string,
    authKeyPair: KeyPair,
    lockId: string,
  ): Promise<MetadataLockStatus> {
    try {
      const payload = this.#generatePayloadForLockRequests(authKeyPair, lockId);

      const url = `${metadataEndpoint}/releaseLock`;
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
      return jsonData.status;
    } catch (error) {
      const errorMessage = (error as Error).message || 'Unknown error';
      throw new MetadataStoreError(
        `failed to release metadata lock: ${errorMessage}`,
      );
    }
  }

  /**
   * Generate the payload for the set or batch set secret data request and get payload signature.
   *
   * @param data - The encrypted secret data to be stored.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param nodeIndex - The index of the Auth Token to be used for authenticating the secret data.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSetSecretDataRequest<
    T extends string | IBatchSetData,
  >(
    data: T,
    authKeyPair: KeyPair,
    nodeIndex: number,
  ): T extends string
    ? ISetSecretDataRequestBody
    : IBatchSetSecretDataRequestBody {
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
    } as T extends string
      ? ISetSecretDataRequestBody
      : IBatchSetSecretDataRequestBody;
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
   * Generate the payload for the lock requests.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param lockId - The lock id to be released.
   * @returns The payload for the lock requests.
   */
  #generatePayloadForLockRequests(
    authKeyPair: KeyPair,
    lockId?: string,
  ): IMetadataLockRequestBody {
    const { pubKey: pubKeyRaw, privKey } = authKeyPair;
    const data = { timestamp: Date.now() };
    // metadata server expects der encoded signature for lock requests
    const shouldDerEncoded = true;
    const signature = this.#generatePayloadSignature(
      data,
      privKey,
      shouldDerEncoded,
    );
    const key = bytesToHex(pubKeyRaw);

    const payloadForLockRequest: IMetadataLockRequestBody = {
      data,
      signature,
      key,
      id: lockId,
    };

    return payloadForLockRequest;
  }

  /**
   * Generate the signature for the payload.
   *
   * @param payload - The payload to be signed.
   * @param privKey - The private key to sign the payload.
   * @param shouldDerEncoded - Whether to return the signature in der encoded format.
   * @returns The signature hex string.
   */
  #generatePayloadSignature(
    payload: Record<string, unknown>,
    privKey: bigint,
    shouldDerEncoded = false,
  ): string {
    const payloadString = safeStringify(payload);
    const hash = keccak256(payloadString);
    const signature = secp256k1.sign(hash, privKey);

    if (shouldDerEncoded) {
      return signature.toDERHex();
    }

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
