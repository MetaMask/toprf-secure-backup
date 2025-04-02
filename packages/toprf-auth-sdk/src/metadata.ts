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

import { DEFAULT_METADATA_SERVER_URL } from './constants';
import type {
  FetchSecretDataResult,
  IBatchSetData,
  IBatchSetSecretDataRequestBody,
  IGetSecretDataRequestBody,
  IMetadataLockRequestBody,
  ISetSecretDataRequestBody,
} from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';

export enum MetadataStorageLocation {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  METADATA_SERVER = 'metadata-server',
  // eslint-disable-next-line @typescript-eslint/naming-convention
  PROFILE_SYNC = 'profile-sync',
}

export enum MetadataLockStatus {
  FAILED = 0,
  SUCCESS = 1,
}

type MetadataStoreOptions = {
  authToken: string;
  storageLocation?: MetadataStorageLocation;
  metadataServerUrl?: string;
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

  readonly #metadataServerUrl: string = '';

  readonly #authToken: string;

  /**
   *
   * @param options - The initialization options for the metadata store.
   * @param options.authToken - The auth token to be used for authenticating requests to the metadata server.
   * @param options.storageLocation - The storage location of the metadata.
   * @param options.metadataServerUrl - The metadata server URL.
   */
  constructor({
    authToken,
    storageLocation = MetadataStorageLocation.METADATA_SERVER,
    metadataServerUrl = DEFAULT_METADATA_SERVER_URL,
  }: MetadataStoreOptions) {
    this.#storageLocation = storageLocation;
    this.#authToken = authToken;

    if (storageLocation === MetadataStorageLocation.METADATA_SERVER) {
      this.#metadataServerUrl = metadataServerUrl;
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
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns A promise that resolves when the secret data is stored.
   */
  async storeSecretData(secretData: string, seed: Uint8Array): Promise<void> {
    await this.#setData(secretData, seed);
  }

  /**
   * Encrypts the secret data and stores it in the metadata store.
   *
   * @param secretData - The array of secret data to be stored.
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns A promise that resolves when the secret data is stored.
   */
  async storeSecretDataBatch(
    secretData: string[],
    seed: Uint8Array,
  ): Promise<void> {
    await this.#batchSetData(secretData, seed);
  }

  /**
   * Fetches the secret data from the metadata store and decrypts it.
   *
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async fetchSecretData(
    seed: Uint8Array,
  ): Promise<FetchSecretDataResult | null> {
    return await this.#getData(seed);
  }

  /**
   * Acquires a lock on the metadata store.
   *
   * @param seed - The seed to derive the user public key.
   * @returns A promise that resolves with the lock id.
   */
  async acquireMetadataLock(seed: Uint8Array): Promise<string> {
    const { status, id: lockId } = await this.#acquireLock(seed);
    if (status !== MetadataLockStatus.SUCCESS) {
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
   * @param seed - The seed to derive the user public key.
   * @param lockId - The lock id to be released.
   * @returns A promise that resolves with the lock status.
   */
  async releaseMetadataLock(
    seed: Uint8Array,
    lockId: string,
  ): Promise<MetadataLockStatus> {
    return await this.#releaseLock(seed, lockId);
  }

  /**
   * Encrypts the secret data and inserts or updates it in the metadata store.
   *
   * @param secretData - The secret data to be stored.
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #setData(secretData: string, seed: Uint8Array): Promise<void> {
    try {
      const url = this.#computeMetadataServerUrl('set');
      const encryptedData = this.#encryptData(secretData, seed);
      const payload =
        this.#generatePayloadForSetOrBatchSetSecretDataRequest<string>(
          encryptedData,
          seed,
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
   * @param secretData - The array of secret data to be stored.
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns A promise that resolves when the secret data is stored.
   */
  async #batchSetData(secretData: string[], seed: Uint8Array): Promise<void> {
    try {
      const url = this.#computeMetadataServerUrl('batch_set');
      const encryptedDataArray = secretData.map((secret) => ({
        data: this.#encryptData(secret, seed),
      }));

      const payload =
        this.#generatePayloadForSetOrBatchSetSecretDataRequest<IBatchSetData>(
          encryptedDataArray,
          seed,
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
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns A promise that resolves with the decrypted secret data.
   */
  async #getData(seed: Uint8Array): Promise<FetchSecretDataResult | null> {
    try {
      const url = this.#computeMetadataServerUrl('get');
      const payload = this.#generatePayloadForGetSecretDataRequest(seed);

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

      const encryptionKey = deriveEncryptionKey(seed);
      const secretData = jsonData.data.map((data: string) =>
        this.#decryptData(data, encryptionKey),
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
   * @param seed - The seed to derive the user public key.
   * @returns A promise that resolves when the lock is acquired.
   */
  async #acquireLock(
    seed: Uint8Array,
  ): Promise<{ status: MetadataLockStatus; id?: string }> {
    try {
      const payload = this.#generatePayloadForLockRequests(seed);
      const url = this.#computeMetadataServerUrl('acquireLock');

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
   * @param seed - The seed to derive the user public key.
   * @param lockId - The lock id to be released.
   * @returns A promise that resolves with the lock status.
   */
  async #releaseLock(
    seed: Uint8Array,
    lockId: string,
  ): Promise<MetadataLockStatus> {
    try {
      const payload = this.#generatePayloadForLockRequests(seed, lockId);

      const url = this.#computeMetadataServerUrl('releaseLock');
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
   * Computes the metadata server URL for the given operation.
   *
   * @param operation - The operation to be performed on the metadata server.
   * @returns The metadata server URL.
   */
  #computeMetadataServerUrl(
    operation: 'set' | 'get' | 'batch_set' | 'acquireLock' | 'releaseLock',
  ): string {
    this.#assertIsUsingMetadataServer();
    let baseUrl = this.#metadataServerUrl;

    if (operation !== 'acquireLock' && operation !== 'releaseLock') {
      baseUrl = `${baseUrl}/enc_account_data`;
    }

    return `${baseUrl}/${operation}`;
  }

  /**
   * Asserts that the metadata store is using the metadata server.
   *
   * This assertion is called before making any requests to the metadata server.
   *
   */
  #assertIsUsingMetadataServer(): void {
    if (this.#storageLocation !== MetadataStorageLocation.METADATA_SERVER) {
      // TODO: use error constants
      throw new Error('Metadata store is not using metadata server');
    }
  }

  /**
   * Generate the payload for the set or batch set secret data request and get payload signature.
   *
   * @param data - The encrypted secret data to be stored.
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns The payload for the batch set secret data request.
   */
  #generatePayloadForSetOrBatchSetSecretDataRequest<
    T extends string | IBatchSetData,
  >(
    data: T,
    seed: Uint8Array,
  ): T extends string
    ? ISetSecretDataRequestBody
    : IBatchSetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const authToken = this.#authToken;

    const { pk: pubKeyRaw, sk: privKey } = deriveAuthenticationKeyPair(seed);
    const pubKey = bytesToHex(pubKeyRaw);
    const signature = this.#generatePayloadSignature(
      { data, timestamp, feature, authToken },
      privKey,
    );

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
   * @param seed - The seed to derive the encryption/authentication key from.
   * @returns The payload for the get secret data request.
   */
  #generatePayloadForGetSecretDataRequest(
    seed: Uint8Array,
  ): IGetSecretDataRequestBody {
    const timestamp = Date.now().toString();
    const feature = this.#feature;
    const authToken = this.#authToken;
    const { pk: pubKeyRaw, sk: privKey } = deriveAuthenticationKeyPair(seed);

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
   * @param seed - The seed to derive the user public key.
   * @param lockId - The lock id to be released.
   * @returns The payload for the lock requests.
   */
  #generatePayloadForLockRequests(
    seed: Uint8Array,
    lockId?: string,
  ): IMetadataLockRequestBody {
    const { pk: pubKeyRaw, sk: privKey } = deriveAuthenticationKeyPair(seed);
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
   * Derive AES-256 key from seed and encrypt the data using the key.
   *
   * We might not need it if we're using Profile-Sync SDK since encryption is handled in the SDK
   *
   * @param data - The secret data to be encrypted.
   * @param seed - The seed to derive the encryption key from.
   * @returns The encrypted data.
   */
  #encryptData(data: string, seed: Uint8Array): string {
    const encryptionKey = deriveEncryptionKey(seed);
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
