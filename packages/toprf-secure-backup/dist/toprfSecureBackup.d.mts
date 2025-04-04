import type { TORUS_SAPPHIRE_NETWORK_TYPE } from "@toruslabs/constants";
import type { AuthenticateParams, AuthenticateResult, CreateEncryptionKeyParams, CreateEncryptionKeyResult, FetchAllSecretDataParams, FetchSecretDataResult, IToprfSecureBackup, RecoverEncryptionKeyParams, RecoverEncryptionKeyResult, AddSecretDataItemParams, CreateLocalEncryptionKeyParams, CreateLocalEncryptionKeyResult } from "./interfaces.mjs";
/**
 *
 */
export declare class ToprfSecureBackup implements Partial<IToprfSecureBackup> {
    #private;
    /**
     *
     * @param params - The parameters for the constructor.
     * @param params.network - The web3auth network to be used key management and authentication.
     */
    constructor(params: {
        network: TORUS_SAPPHIRE_NETWORK_TYPE;
    });
    /**
     * This function is used to authenticate the user by sending the oauth idToken to the nodes and
     * getting the authentication tokens from the nodes in return.
     *
     * @param params - The authentication parameters.
     * @param params.idTokens - An array of ID tokens for authentication.
     * @param params.verifier - The verifier who issued the idToken.
     * @param params.verifierID - The verifierID/userID assigned to the user by the verifier.
     *
     * @returns A promise that resolves with the authentication result.
     * @throws {Error} If idToken is older than 6 minutes.
     */
    authenticate(params: AuthenticateParams): Promise<AuthenticateResult>;
    /**
     * This function creates the oprf encryption key seed and authentication key pair.
     *
     * @param params - The parameters for creating the encryption key.
     * @param params.password - New password of the user.
     *
     * @returns A promise that resolves with the encryption key.
     */
    createLocalEncKey(params: CreateLocalEncryptionKeyParams): CreateLocalEncryptionKeyResult;
    /**
     * This function creates the encryption key which is used to encrypt/decrypt the secret data.
     *
     * @param params - The parameters for creating the encryption key.
     * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
     * @param params.password - New password of the user.
     *
     * @returns A promise that resolves with the encryption key.
     */
    createEncKey(params: CreateEncryptionKeyParams): Promise<CreateEncryptionKeyResult>;
    /**
     * This function recovers the encryption key which is used to decrypt the secret data.
     *
     * @param params - The parameters for recovering the encryption key.
     * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
     * @param params.password - The password of the user.
     * @param params.verifier - The verifier name used for authentication.
     * @param params.verifierId - The verifierId/userID of the user.
     *
     * @returns A promise that resolves with the encryption key.
     */
    recoverEncKey(params: RecoverEncryptionKeyParams): Promise<RecoverEncryptionKeyResult>;
    /**
     * This function encrypts the secret data using the encryption key and stores it nodes metadata store in encrypted form.
     *
     * @param params - The parameters for registering new secret data.
     * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
     * @param params.encKey - The encryption key which is used to encrypt the secret data before storing it.
     * @param params.secretData - The array of secret data to be registered.
     * @param params.authKeyPair - The authentication key pair which is used to authenticate the user to the storage service.
     *
     * @returns A promise that resolves when the secret data is stored.
     */
    addSecretDataItem(params: AddSecretDataItemParams): Promise<void>;
    /**
     * This function fetches all secret data items associated with the given
     * auth pub key, decrypts, and returns them.
     *
     * @param params - The parameters for fetching the secret data.
     * @param params.decKey - The decryption key to be used to decrypt the secret data.
     * @param params.authKeyPair - The authentication key to be used to provide valid signature for fetching the secret data.
     *
     * @returns A promise that resolves with the decrypted secret data. Null if no secret data is found.
     */
    fetchAllSecretDataItems(params: FetchAllSecretDataParams): Promise<FetchSecretDataResult | null>;
}
//# sourceMappingURL=toprfSecureBackup.d.mts.map