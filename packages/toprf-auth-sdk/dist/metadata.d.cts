import type { FetchSecretDataResult } from "./interfaces.cjs";
export declare enum MetadataStorageLocation {
    METADATA_SERVER = "metadata-server",
    PROFILE_SYNC = "profile-sync"
}
export declare enum MetadataLockStatus {
    FAILED = 0,
    SUCCESS = 1
}
type MetadataStoreOptions = {
    authToken: string;
    storageLocation?: MetadataStorageLocation;
    metadataServerUrl?: string;
};
/**
 * Error class for metadata store.
 */
export declare class MetadataStoreError extends Error {
    /**
     * Constructor for MetadataStoreError.
     *
     * @param message - The error message.
     */
    constructor(message: string);
}
/**
 * MetadataStore class.
 *
 * This class is used to store and retrieve encrypted account metadata for the
 * given feature.
 */
export declare class MetadataStore {
    #private;
    /**
     *
     * @param options - The initialization options for the metadata store.
     * @param options.authToken - The auth token to be used for authenticating requests to the metadata server.
     * @param options.storageLocation - The storage location of the metadata.
     * @param options.metadataServerUrl - The metadata server URL.
     */
    constructor({ authToken, storageLocation, metadataServerUrl, }: MetadataStoreOptions);
    /**
     * Get the storage location of the metadata.
     *
     * @returns The storage location of the metadata.
     */
    get metadataStorageLocation(): MetadataStorageLocation;
    /**
     * Encrypts the secret data and stores it in the metadata store.
     *
     * @param secretData - The secret data to be stored.
     * @param seed - The seed to derive the encryption/authentication key from.
     * @returns A promise that resolves when the secret data is stored.
     */
    storeSecretData(secretData: string, seed: Uint8Array): Promise<void>;
    /**
     * Encrypts the secret data and stores it in the metadata store.
     *
     * @param secretData - The array of secret data to be stored.
     * @param seed - The seed to derive the encryption/authentication key from.
     * @returns A promise that resolves when the secret data is stored.
     */
    storeSecretDataBatch(secretData: string[], seed: Uint8Array): Promise<void>;
    /**
     * Fetches the secret data from the metadata store and decrypts it.
     *
     * @param seed - The seed to derive the encryption/authentication key from.
     * @returns A promise that resolves with the decrypted secret data.
     */
    fetchSecretData(seed: Uint8Array): Promise<FetchSecretDataResult | null>;
    /**
     * Acquires a lock on the metadata store.
     *
     * @param seed - The seed to derive the user public key.
     * @returns A promise that resolves with the lock id.
     */
    acquireMetadataLock(seed: Uint8Array): Promise<string>;
    /**
     * Releases the lock on the metadata store.
     *
     * @param seed - The seed to derive the user public key.
     * @param lockId - The lock id to be released.
     * @returns A promise that resolves with the lock status.
     */
    releaseMetadataLock(seed: Uint8Array, lockId: string): Promise<MetadataLockStatus>;
}
export {};
//# sourceMappingURL=metadata.d.cts.map