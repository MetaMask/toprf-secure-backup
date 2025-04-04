import type { FetchSecretDataResult, KeyPair, AddSecretDataItemParams } from "./interfaces.cjs";
type MetadataStoreOptions = {
    nodeEndpointsMap: Map<number, string>;
};
export type AuthTokenToMetadataEndpointsMap = Record<string, string>;
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
     * @param options.nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
     * @param options.storageLocation - The storage location of the metadata.
     */
    constructor(options: MetadataStoreOptions);
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
    addSecretDataItem(params: AddSecretDataItemParams): Promise<void>;
    /**
     * Fetches the secret data from the metadata store and decrypts it.
     *
     * @param encKey - The encryption key to be used for decrypting the secret data.
     * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
     * @returns A promise that resolves with the decrypted secret data.
     */
    fetchAllSecretDataItems(encKey: Uint8Array, authKeyPair: KeyPair): Promise<FetchSecretDataResult>;
}
export {};
//# sourceMappingURL=metadata.d.cts.map