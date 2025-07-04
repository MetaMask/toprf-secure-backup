import { safeStringify } from '@metamask/auth-network-utils';
import { gcm } from '@noble/ciphers/aes';
import { managedNonce } from '@noble/ciphers/webcrypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';

import { PW_BACKUP_ITEM_ID } from './constants';
import type {
  IGetSecretDataRequestBody,
  KeyPair,
  IAddSecretDataRequestBody,
  IBatchAddSecretDataRequestBody,
  IMetadataLockRequestBody,
  NodeAuthToken,
  BaseAddSecretDataItemParams,
} from './interfaces';

type MetadataStoreOptions = {
  metadataEndpoint: string;
} & (
  | { accessToken: string; apiKey?: string }
  | { accessToken?: string; apiKey: string }
);

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

export type SecretDataItem = {
  itemId?: string;
  data: Uint8Array;
};

export type MetadataAddSecretDataItemParams =
  BaseAddSecretDataItemParams<SecretDataItem>;

export type MetadataBatchAddSecretDataItemParams = BaseAddSecretDataItemParams<
  SecretDataItem[],
  Uint8Array | Uint8Array[]
>;

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

  readonly #accessToken?: string;

  readonly #apiKey?: string;

  /**
   *
   * @param options - The initialization options for the metadata store.
   * @param options.nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
   * @param options.storageLocation - The storage location of the metadata.
   * @param options.accessToken - The access token for the metadata store.
   * @param options.apiKey - The api key for the metadata store.
   */
  constructor(options: MetadataStoreOptions) {
    this.#metadataEndpoint = options.metadataEndpoint;
    this.#accessToken = options.accessToken;
    this.#apiKey = options.apiKey;
  }

  /**
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param params - The parameters for storing the secret data.
   * @param params.secretData - The secret data to be stored.
   * @param params.encKey - The encryption key to be used for encrypting the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async addSecretDataItem(
    params: MetadataAddSecretDataItemParams,
  ): Promise<void> {
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
    params: MetadataBatchAddSecretDataItemParams,
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
   * @param itemId - The item id to be used for fetching the secret data.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async fetchAllSecretDataItems(
    encKey: Uint8Array,
    authKeyPair: KeyPair,
    itemId?: string,
  ): Promise<SecretDataItem[]> {
    try {
      const result = await this.#getAllDataItems({
        encKey,
        authKeyPair,
        metadataEndpoint: this.#metadataEndpoint,
        itemId,
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
    secretData: SecretDataItem;
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
  }): Promise<boolean> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/set`;
      const encryptedData = this.#encryptData(
        params.secretData.data,
        params.encKey,
      );
      const payload = this.#generatePayloadForSetOrBatchSetSecretDataRequest(
        {
          itemId: params.secretData.itemId,
          data: encryptedData,
        },
        params.authKeyPair,
      );
      const requestBody = JSON.stringify(payload);

      const response = await fetch(url, {
        headers: {
          'x-api-key': this.#apiKey || '',
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
   * @param params - The parameters for serializing and making batch set secret
   * data request.
   * @param params.secretData - The array of secret data to be stored.
   * @param params.encKey - The encryption key or keys to be used for encrypting
   * the secret data. If an array is provided, it must have the same length as
   * the secret data array.
   * @param params.authKeyPair - The authentication key pair to be used for
   * authenticating the secret data.
   * @param params.metadataEndpoint - The metadata server endpoint to be used
   * for storing the secret data.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #batchAddData(params: {
    secretData: SecretDataItem[];
    encKey: Uint8Array | Uint8Array[];
    authKeyPair: KeyPair;
    metadataEndpoint: string;
  }): Promise<boolean> {
    const encKeys = (
      Array.isArray(params.encKey)
        ? params.encKey
        : params.secretData.map(() => params.encKey)
    ) as Uint8Array[];

    if (encKeys.length !== params.secretData.length) {
      throw new MetadataStoreError(
        'encKey must be of same length as secretData',
      );
    }

    try {
      const url = `${params.metadataEndpoint}/enc_account_data/batch_set`;
      const encryptedDataArray = params.secretData.map((secret, index) => ({
        data: this.#encryptData(secret.data, encKeys[index]),
        itemId: secret.itemId,
      }));
      const payload = this.#generatePayloadForSetOrBatchSetSecretDataRequest(
        encryptedDataArray,
        params.authKeyPair,
      );

      const response = await fetch(url, {
        headers: {
          'x-api-key': this.#apiKey || '',
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
   * @param params.itemId - The item id to be used for fetching the secret data.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async #getAllDataItems(params: {
    encKey: Uint8Array;
    authKeyPair: KeyPair;
    metadataEndpoint: string;
    itemId?: string;
  }): Promise<SecretDataItem[]> {
    try {
      const url = `${params.metadataEndpoint}/enc_account_data/get`;
      const payload = this.#generatePayloadForGetSecretDataRequest(
        params.authKeyPair,
        params.itemId,
      );

      const response = await fetch(url, {
        headers: {
          'x-api-key': this.#apiKey || '',
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

      const jsonData = (await response.json()) as {
        data: string[];
        ids: string[];
      };
      if (!jsonData.data) {
        throw new MetadataStoreError('Failed to fetch metadata');
      }

      const secretData: SecretDataItem[] = jsonData.data
        .filter((_data, i) => {
          if (params.itemId) {
            return jsonData.ids[i] === params.itemId;
          }
          // Exclude password backup item from regular query.
          return jsonData.ids[i] !== PW_BACKUP_ITEM_ID;
        })
        .map((data: string, index: number) => {
          const rawData = new Uint8Array(Buffer.from(data, 'base64'));
          return {
            itemId: jsonData.ids[index],
            data: this.#decryptData(rawData, params.encKey),
          };
        });
      return secretData.filter((data) => data.data.length > 0);
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
   * @param inputData - The raw encrypted secret data or batch of encrypted secret data to be stored.
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSetSecretDataRequest(
    inputData: SecretDataItem | SecretDataItem[],
    authKeyPair: KeyPair,
  ): IAddSecretDataRequestBody | IBatchAddSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;

    const sigPayload: Record<string, any> = {
      timestamp,
      feature,
    };

    if (Array.isArray(inputData)) {
      sigPayload.data = inputData.map((item) => {
        const dataBytes = item.data;
        return {
          data: Buffer.from(dataBytes).toString('base64'),
          itemId: item.itemId,
        };
      });
    } else {
      sigPayload.data = Buffer.from(inputData.data).toString('base64');
      sigPayload.itemId = inputData.itemId;
    }

    const { pk, sk } = authKeyPair;
    const signature = this.#generatePayloadSignature(sigPayload, sk);

    const pubKey = bytesToHex(pk);

    const payload = {
      ...sigPayload,
      authToken: this.#accessToken,
      signature,
      pubKey,
    } as IAddSecretDataRequestBody | IBatchAddSecretDataRequestBody;

    return payload;
  }

  /**
   * Generate the payload for the get secret data request and get payload signature.
   *
   * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
   * @param itemId - The item id to be used for fetching the secret data.
   * @returns The payload for the get secret data request.
   */
  #generatePayloadForGetSecretDataRequest(
    authKeyPair: KeyPair,
    itemId?: string,
  ): IGetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const { pk, sk } = authKeyPair;

    const signature = this.#generatePayloadSignature(
      { feature, timestamp, itemId },
      sk,
    );

    const pubKey = bytesToHex(pk);

    return {
      authToken: this.#accessToken,
      feature,
      pubKey,
      timestamp,
      signature,
      itemId,
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
