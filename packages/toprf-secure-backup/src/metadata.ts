import { safeStringify } from '@metamask/auth-network-utils';
import { gcm } from '@noble/ciphers/aes';
import { managedNonce } from '@noble/ciphers/webcrypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';

import type {
  FetchSecretDataResult,
  IGetSecretDataRequestBody,
  KeyPair,
  AddSecretDataItemParams,
  ISetSecretDataRequestBody,
  IBatchSetSecretDataRequestBody,
  BatchAddSecretDataItemParams,
  IMetadataLockRequestBody,
  NodeAuthToken,
} from './interfaces';

type MetadataStoreOptions = {
  metadataEndpoint: string;
};

export type MetadataLock = {
  id: string;
  nodeIndex: number;
}[];

export enum MetadataLockStatus {
  FAILED = 0,
  SUCCESS = 1,
}

export type AuthTokenToMetadataEndpointsMap = {
  [endpoint: string]: NodeAuthToken;
};

export type LockAcquiredResponse = { status: MetadataLockStatus; id?: string };

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

  readonly #metadataEndpoint: string;

  /**
   *
   * @param options - The initialization options for the metadata store.
   * @param options.nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
   * @param options.storageLocation - The storage location of the metadata.
   */
  constructor(options: MetadataStoreOptions) {
    this.#metadataEndpoint = options.metadataEndpoint;
  }

  /**
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async addSecretDataItem(params: AddSecretDataItemParams): Promise<void> {
    try {
      const { secretData, encKey, authKeyPair } = params;

      await this.#addData({
        secretData,
        encKey,
        authKeyPair,
        metadataEndpoint: this.#metadataEndpoint,
      });
    } catch (error) {
      throw new MetadataStoreError(
        `failed to add metadata: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The array of secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async batchAddSecretData(
    params: BatchAddSecretDataItemParams,
  ): Promise<void> {
    try {
      const { secretData, encKey, authKeyPair } = params;

      await this.#batchAddData({
        secretData,
        encKey,
        authKeyPair,
        metadataEndpoint: this.#metadataEndpoint,
      });
    } catch (error) {
      throw new MetadataStoreError(
        `failed to add batch metadata: ${(error as Error).message}`,
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
      const result = await this.#getAllDataItems({
        encKey,
        authKeyPair,
        metadataEndpoint: this.#metadataEndpoint,
      });
      return result;
    } catch (error) {
      throw new MetadataStoreError(
        `failed to fetch metadata: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Acquires a lock on the metadata store.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns A promise that resolves with the lock id.
   */
  async acquireMetadataLock(authKeyPair: KeyPair): Promise<string> {
    const { status: lockStatus, id: lockId } = await this.#acquireLock(
      this.#metadataEndpoint,
      authKeyPair,
    );
    if (lockStatus !== MetadataLockStatus.SUCCESS) {
      throw new MetadataStoreError('Failed to acquire metadata lock');
    }
    if (!lockId) {
      throw new MetadataStoreError(
        'Failed to acquire metadata lock. Missing lock id',
      );
    }

    return lockId;
  }

  /**
   * Releases the lock on the metadata store.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param lockId - The lock id to be released.
   * @returns A promise that resolves with the lock status.
   */
  async releaseMetadataLock(
    authKeyPair: KeyPair,
    lockId: string,
  ): Promise<MetadataLockStatus> {
    const lockStatus = await this.#releaseLock(
      this.#metadataEndpoint,
      authKeyPair,
      lockId,
    );

    if (lockStatus !== MetadataLockStatus.SUCCESS) {
      throw new MetadataStoreError(
        `Failed to release metadata lock with id ${lockId}`,
      );
    }

    return lockStatus;
  }

  /**
   * Encrypts the secret data and inserts or appends it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for storing the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #addData(params: {
    secretData: Uint8Array;
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
  }): Promise<boolean> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/set`;
      const encryptedData = this.#encryptData(params.secretData, params.encKey);
      const payload =
        this.#generatePayloadForSetOrBatchSetSecretDataRequest<Uint8Array>(
          encryptedData,
          params.authKeyPair,
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
   * Encrypts the array of secret data and inserts them in the metadata store.
   *
   * @param params - The parameters for serializing and making batch set secret data request.
   * @param params.secretData - The array of secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used for storing the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #batchAddData(params: {
    secretData: Uint8Array[];
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
  }): Promise<boolean> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/batch_set`;
      const encryptedDataArray = params.secretData.map((secret) => ({
        data: this.#encryptData(secret, params.encKey),
      }));
      const payload = this.#generatePayloadForSetOrBatchSetSecretDataRequest<
        { data: Uint8Array }[]
      >(encryptedDataArray, params.authKeyPair);

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

      const secretData = jsonData.data.map((data: string) => {
        const rawData = new Uint8Array(Buffer.from(data, 'base64'));
        return this.#decryptData(rawData, params.encKey);
      });
      return secretData;
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
  ): Promise<LockAcquiredResponse> {
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
   * @param rawData - The raw encrypted secret data or batch of encrypted secret data to be stored.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSetSecretDataRequest<
    RawDataType extends Uint8Array | { data: Uint8Array }[],
  >(
    rawData: RawDataType,
    authKeyPair: KeyPair,
  ): RawDataType extends Uint8Array
    ? ISetSecretDataRequestBody
    : IBatchSetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;

    let base64EncodedData: string | { data: string }[];

    if (Array.isArray(rawData)) {
      base64EncodedData = rawData.map((item) => {
        const dataBytes = item.data;
        return {
          data: Buffer.from(dataBytes).toString('base64'),
        };
      });
    } else {
      base64EncodedData = Buffer.from(rawData).toString('base64');
    }

    const { pk, sk } = authKeyPair;
    const signature = this.#generatePayloadSignature(
      { data: base64EncodedData, timestamp, feature },
      sk,
    );

    const pubKey = bytesToHex(pk);

    return {
      data: base64EncodedData,
      signature,
      feature,
      timestamp,
      pubKey,
    } as RawDataType extends Uint8Array
      ? ISetSecretDataRequestBody
      : IBatchSetSecretDataRequestBody;
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
    const { pk, sk } = authKeyPair;
    const data = { timestamp: Date.now() };
    // metadata server expects der encoded signature for lock requests
    const shouldDerEncoded = true;
    const signature = this.#generatePayloadSignature(
      data,
      sk,
      shouldDerEncoded,
    );
    const key = bytesToHex(pk);

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
   * @param shouldDerEncoded - Whether the signature should be der encoded.
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
