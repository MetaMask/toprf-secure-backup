import type { INodePub } from '@toruslabs/constants';

/**
 * SEC1 encoded public key
 */
export type SEC1EncodedPublicKey = Uint8Array;

/**
 * KeyPair - The encryption/decryption private and public key pair.
 *
 * sk - The decryption private key in bigint format.
 *
 * pk - The encryption public key in SEC1 encoded format.
 */
export type KeyPair = {
  sk: bigint;
  pk: SEC1EncodedPublicKey;
};

/**
 * Optional override for node details.
 */
export type NodeDetailsOverride = {
  /**
   * Endpoint configuration. This allows for overriding the default SSS node endpoints.
   *
   * - **To use FND-resolved node URLs with a custom path:** Provide a single `string`
   * representing the path to be appended to each FND-resolved node URL.
   * For example, `'/sss-toprf'` will transform FND URLs like `https://node1.example.com`
   * into `https://node1.example.com/sss-toprf`.
   *
   * - **To use a completely custom set of node URLs (bypassing FND resolution):**
   * Provide an array of `string[]` where each string is a complete endpoint URL.
   * For example, `['https://custom-node1.com/custom-path', 'https://custom-node2.com/custom-path']`.
   *
   * If left `undefined`, the SDK will use the default FND-resolved SSS endpoints directly.
   */
  endpoints?: string | string[];
  /**
   * Array of node indexes. Must match network node count if provided.
   */
  indexes?: number[];
  /**
   * Array of node public keys. Must match network node count if provided.
   */
  pubKeys?: INodePub[];
};

/**
 * AuthenticateParams - The parameters for the authenticate request.
 *
 * idTokens - The idTokens to be used for the authenticate request.
 *
 * authConnectionId - The auth connection name to be used for the authenticate request.
 *
 * groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request with aggregate (single id) verifier.
 *
 * userId - The user id of the user to be used for the authenticate request.
 *
 * groupedAuthConnectionParams - Optional groupedAuthConnectionParams to be used for the authenticate request.
 * You can pass this to use aggregate verifier.
 */
export type AuthenticateParams = {
  // for now we only support one idToken, in future we will support multiple to remove commitment call
  // so leaving it as an array for future use
  idTokens: string[];
  authConnectionId: string;
  userId: string;
  groupedAuthConnectionId?: string;
};

/**
 * NodeAuthToken - An authentication token and the node details.
 *
 * authToken - The authentication token.
 *
 * nodeIndex - The index of the node that issued the token.
 *
 * nodePubKey - The public key of the node that issued the token.
 */
export type NodeAuthToken = {
  authToken: string;
  nodeIndex: number;
  nodePubKey: string;
};
/**
 * nodeAuthTokens - An array of authentication tokens issued by the nodes.
 */
export type NodeAuthTokens = NodeAuthToken[];

/**
 * nodeAuthTokens - An array of authentication tokens issued by the nodes.
 *
 * isNewUser - Indicates if the user has completed the key setup process or not.
 * if `true` then the user hasn't completed the social + password setup process.
 * if `false` then the user has completed the social + password setup process.
 */
export type AuthenticateResult = {
  nodeAuthTokens: NodeAuthTokens;
  isNewUser: boolean;
};

/**
 * CreateLocalKeyParams - The parameters for creating an OPRF encryption key locally.
 *
 * password - The password of the user.
 *
 * oprfKey - Optional OPRF key to be used for the OPRF evaluation.
 */
export type CreateLocalKeyParams = {
  password: string;
  oprfKey?: bigint;
};

/**
 * CreateLocalKeyResult - The result of creating an encryption key.
 *
 * oprfKey - The OPRF key which is used to for local OPRF evaluation.
 *
 * seed - The seed which is used to derive the authentication and encryption keys.
 *
 * authKeyPair - The authentication key pair which is used to authenticate the user.
 *
 * encKey - The encryption key which is used to encrypt the secret data.
 */
export type CreateLocalKeyResult = {
  oprfKey: bigint;
  seed: Uint8Array;
  authKeyPair: KeyPair;
  encKey: Uint8Array;
  pwEncKey: Uint8Array;
};

/**
 * PersistLocalKeyParams - The parameters for persisting an OPRF key's shares to the servers.
 *
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * oprfKey - The OPRF key which is used to for local OPRF evaluation.
 *
 * authPubKey - The authentication public key which is used to authenticate the write request to the metadata store.
 *
 * authConnectionId - The auth connection name used for authentication.
 *
 * userId - The user id of the user issued by authentication service.
 *
 * groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request with aggregate (single id) verifier.
 *
 * keyShareIndex - Optional key share index to be persisted.
 *
 * oldAuthKeyPair - Optional authentication key pair to be used for key change flow.
 */
export type PersistLocalKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  oprfKey: bigint;
  authPubKey: SEC1EncodedPublicKey;
  authConnectionId: string;
  userId: string;
  groupedAuthConnectionId?: string;
  keyShareIndex?: number;
  oldAuthKeyPair?: KeyPair;
};

/**
 * CreateEncryptionKeyParams - The parameters for creating an encryption key.
 *
 * authConnectionId - The auth connection name of the user.
 *
 * userId - The user id of the user issued by authentication service.
 *
 * nodeAuthTokens - The tokens issued by the nodes on verifying the idTokens.
 *
 * password - The password of the user.
 *
 * groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request with aggregate (single id) verifier.
 */
export type CreateEncryptionKeyParams = {
  authConnectionId: string;
  userId: string;
  nodeAuthTokens: NodeAuthTokens;
  password: string;
  groupedAuthConnectionId?: string;
};

/**
 * CreateEncryptionKeyResult - The result of creating an encryption key.
 *
 * authKeyPair - The authentication key pair which is used to authenticate the user.
 *
 * encKey - The encryption key which is used to encrypt the secret data.
 *
 * pwEncKey - The password encryption key which is used to encrypt the password.
 */
export type CreateEncryptionKeyResult = {
  authKeyPair: KeyPair;
  encKey: Uint8Array;
  pwEncKey: Uint8Array;
};

export type BaseAddSecretDataItemParams<
  SecretDataType,
  EncKeyType = Uint8Array,
> = {
  /**
   * The secret data to be stored.
   */
  secretData: SecretDataType;

  /**
   * The encryption key to be used to encrypt the secret data.
   */
  encKey: EncKeyType;

  /**
   * The authentication key to be used to provide valid signature for storing the secret data.
   */
  authKeyPair: KeyPair;
};

/**
 * encKey - The encryption key to be used to encrypt the secret data before storing it.
 *
 * authKeyPair - The authentication key to be used to provide valid signature for storing the secret data.
 *
 * secretData - The secret data to be stored.
 */
export type AddSecretDataItemParams = BaseAddSecretDataItemParams<Uint8Array>;

export type BatchAddSecretDataItemParams = BaseAddSecretDataItemParams<
  Uint8Array[],
  Uint8Array | Uint8Array[]
>;

/**
 * RecoverEncryptionKeyParams - The parameters for recovering the encryption key.
 *
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * password - The password of the user.
 *
 * authConnectionId - The auth connection name used for authentication.
 *
 * userId - The user id of the user issued by authentication service.
 *
 * groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request with aggregate (single id) verifier.
 */
export type RecoverEncryptionKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  password: string;
  authConnectionId: string;
  userId: string;
  groupedAuthConnectionId?: string;
};

/**
 * authKeyPair - The authentication key pair which is used to authenticate the user.
 * encKey - The encryption key which is used to encrypt the secret data.
 * keyShareIndex - The index of the key shares on the nodes, used for key change operations.
 * rateLimitResetResult - A promise that resolves when the rate limit is reset.
 */
export type RecoverEncryptionKeyResult = {
  authKeyPair: KeyPair;
  encKey: Uint8Array;
  pwEncKey: Uint8Array;
  keyShareIndex: number;
  rateLimitResetResult: Promise<void>;
};

/**
 * Parameters for changing the encryption key.
 *
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * authConnectionId - The auth connection name used for authentication.
 *
 * userId - The user id of the user issued by authentication service.
 *
 * oldEncKey - The old encryption key of the user.
 *
 * oldAuthKeyPair - The old authentication key pair of the user.
 *
 * newKeyShareIndex - The key share index to be used for the new key.
 *
 * newPassword - Optional new password of the user, either this or pregeneratedOprfKey is required.
 *
 * groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request with aggregate (single id) verifier.
 *
 * pregeneratedOprfKey - Optional pregenerated OPRF key to be used for the key change, if not provided, a new key will be generated from the new password.
 */
export type ChangeEncryptionKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  authConnectionId: string;
  userId: string;
  oldEncKey: Uint8Array;
  oldPwEncKey: Uint8Array;
  oldAuthKeyPair: KeyPair;
  newKeyShareIndex: number;
  newPassword?: string;
  groupedAuthConnectionId?: string;
  pregeneratedOprfKey?: CreateLocalKeyResult;
};

/**
 * authKeyPair - The new authentication key pair which is used to authenticate the user.
 * encKey - The new encryption key which is used to encrypt the secret data.
 */
export type ChangeEncryptionKeyResult = {
  authKeyPair: KeyPair;
  encKey: Uint8Array;
  pwEncKey: Uint8Array;
};

/**
 * keyPair - The encryption/decryption key pair which is used to decrypt the secret data.
 */
export type FetchAllSecretDataParams = {
  /**
   * The decryption key to be used to decrypt the secret data.
   */
  decKey: Uint8Array;

  /**
   * The authentication key to be used to provide valid signature for fetching the secret data.
   */
  authKeyPair: KeyPair;
};

/**
 * Proof that the user owns the old key when changing to a new password/key
 * Contains a signature created with the old private key on a timestamp and new key share data.
 */
export type KeyChangeProof = {
  oldKeySignature: string;
  signatureTimestamp: number;
};

/**
 * FetchAuthPubKeyParams - The parameters for fetching the authentication public key.
 *
 * nodeAuthTokens - Auth tokens issued by nodes.
 *
 * authConnectionId - The auth connection name used for authentication.
 *
 * groupedAuthConnectionId - Optional grouped auth connection id to be used for the authenticate request with aggregate (single id) verifier.
 *
 * userId - The user id of the user issued by authentication service.
 */
export type FetchAuthPubKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  authConnectionId: string;
  groupedAuthConnectionId?: string;
  userId: string;
};

export type FetchAuthPubKeyResult = {
  authPubKey: SEC1EncodedPublicKey;
  keyIndex: number;
};

export type RecoverPwEncKeyParams = {
  targetAuthPubKey: SEC1EncodedPublicKey;
  curPwEncKey: Uint8Array;
  curAuthKeyPair: KeyPair;
  maxPwChainLength?: number;
};

export type RecoverPwEncKeyResult = {
  pwEncKey: Uint8Array;
};

export type IToprfSecureBackup = {
  authenticate: (params: AuthenticateParams) => Promise<AuthenticateResult>;

  /**
   * This function locally creates an OPRF and encryption key without storing it at the key
   * management service. It returns the OPRF key, derives the corresponding key
   * seed, authentication key pair and encryption key.
   *
   * @param params - The parameters for creating the encryption key.
   * @param params.password - New password of the user.
   * @param params.oprfKey - Optional OPRF key to be used for the OPRF evaluation.
   *
   * @returns A promise that resolves with the encryption key.
   */
  createLocalKey: (
    params: CreateLocalKeyParams,
  ) => Promise<CreateLocalKeyResult>;

  /**
   * This function persists an locally created OPRF key's shares to the servers.
   *
   * @param params - The parameters for persisting an OPRF key's shares.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.oprfKey - The OPRF key to be persisted.
   * @param params.authKeyPair - The authentication key pair which is used to authenticate the write request to the metadata store.
   * @param params.authConnectionId - The auth connection name used for authentication.
   * @param params.userId - The user id of the user issued by authentication service.
   * @param params.keyShareIndex - The key share index to be persisted. Required only during key change, defaults to FIRST_KEY_INDEX for first-time storage.
   * @param params.oldAuthKeyPair - The old authentication key pair of the user. Required only during key change, not needed for first-time storage.
   * @returns A promise that resolves when the OPRF key's shares are persisted.
   */
  persistLocalKey: (params: PersistLocalKeyParams) => Promise<void>;

  createAndPersistEncKey: (
    params: CreateEncryptionKeyParams,
  ) => Promise<CreateEncryptionKeyResult>;

  recoverEncKey: (
    params: RecoverEncryptionKeyParams,
  ) => Promise<RecoverEncryptionKeyResult>;

  /**
   * This function replaces the existing encryption key with a new one and copies the secret data of existing encryption key to the new one.
   *
   * @param params - The parameters for changing the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.newPassword - The new password of the user.
   * @param params.keyPair - The current encryption key of the user.
   *
   * @returns A promise that resolves with the new encryption key.
   */
  changeEncKey: (
    params: ChangeEncryptionKeyParams,
  ) => Promise<ChangeEncryptionKeyResult>;

  /**
   * This function encrypts the secret data using the encryption key and stores it nodes metadata store in encrypted form.
   *
   * @param params - The parameters for registering new secret data.
   * @param params.encKey - The encryption key to be used to encrypt the secret data before storing it.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for storing the secret data.
   * @param params.secretData - The array of secret data to be registered.
   *
   * @returns A promise that resolves when the secret data is registered.
   */
  addSecretDataItem: (params: AddSecretDataItemParams) => Promise<void>;

  /**
   * This function encrypts the array of secret data using the encryption key and stores it in the metadata store in encrypted form as a batch.
   *
   * @param params - The parameters for registering new secret data.
   * @param params.encKey - The encryption key to be used to encrypt the secret data before storing it.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for storing the secret data.
   * @param params.secretData - The array of secret data to be stored.
   *
   * @returns A promise that resolves when the secret data is stored.
   */
  batchAddSecretDataItems: (
    params: BatchAddSecretDataItemParams,
  ) => Promise<void>;

  /**
   * This function fetches all secret data items associated with the given
   * auth pub key, decrypts, and returns them.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.decKey - The decryption key to be used to decrypt the secret data.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for fetching the secret data.
   *
   * @returns {Uint8Array[]} A promise that resolves with the array of decrypted secret data.
   */
  fetchAllSecretDataItems: (
    params: FetchAllSecretDataParams,
  ) => Promise<Uint8Array[]>;

  /**
   * This function fetches the authentication public key.
   *
   * @param params - The parameters for fetching the authentication public key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.authConnectionId - The auth connection name used for authentication.
   * @param params.userId - The user id of the user issued by authentication service.
   *
   * @returns A promise that resolves with the authentication public key.
   */
  fetchAuthPubKey: (
    params: FetchAuthPubKeyParams,
  ) => Promise<FetchAuthPubKeyResult>;

  /**
   * This function recovers the password encryption key of the user.
   *
   * @param params - The parameters for recovering the password encryption key.
   * @param params.targetAuthPubKey - The public key of the target encryption key.
   * @param params.curPwEncKey - The current password encryption key of the user.
   * @param params.curAuthKeyPair - The current authentication key pair of the user.
   *
   * @returns A promise that resolves to the password encryption key of the user.
   */
  recoverPwEncKey: (
    params: RecoverPwEncKeyParams,
  ) => Promise<RecoverPwEncKeyResult>;
};

/**
 * Base payload structure for metadata request
 */
export type IBaseMetadataRequestBody = {
  /**
   * The feature name related to the secret data
   */
  feature: string;
  /**
   * The public key of the user
   */
  pubKey: string;
  /**
   * The Unix timestamp when the request payload is created along with the signature.
   *
   */
  timestamp: string;
};

/**
 * The array of secret data to be stored in batch request
 */
export type IBatchAddData = {
  /**
   * The base64-encoded string of the secret data
   */
  data: string;
  /**
   * The version of the Metadata Store
   */
  version?: string;
}[];

/**
 * Payload structure for storing secret data
 */
export type IBaseAddSecretDataRequestBody<DataType> =
  IBaseMetadataRequestBody & {
    /**
     * The authentication token of the user issued by authentication service.
     * this token is also known as `metadataAccessToken`.
     */
    authToken?: string;
    /**
     * The secret data to be stored.
     *
     * For storing the single secret data, the data should be base64-encoded string.
     *
     * @example
     * ```ts
     * const data = Buffer.from('SECRET_DATA').toString('base64');
     * ```
     *
     * For storing the batch of secret data, the data should be an array of `IBatchAddData`.
     *
     * @example
     * ```ts
     * const data = [
     *   { data: Buffer.from('SECRET_DATA_1').toString('base64') },
     *   { data: Buffer.from('SECRET_DATA_2').toString('base64') },
     * ];
     * ```
     */
    data: DataType;
    /**
     * The signature produced by signing the payload (without pubKey field) using the user's private key.
     *
     * Sample signature: sign(keccak256(data, feature, authToken, timestamp))
     */
    signature: string;
  };

/**
 * Payload structure for storing secret data for single secret data
 */
export type IAddSecretDataRequestBody =
  IBaseAddSecretDataRequestBody<string> & {
    /**
     * The version of the secret data
     */
    version?: string;
    /**
     * The item id to be used for storing the secret data.
     */
    itemId?: string;
  };

/**
 * Payload structure for storing secret data in batch request
 */
export type IBatchAddSecretDataRequestBody =
  IBaseAddSecretDataRequestBody<IBatchAddData>;

/**
 * Payload structure for fetching secret data
 */
export type IGetSecretDataRequestBody = IBaseMetadataRequestBody & {
  /**
   * The authentication token of the user issued by the SSS services
   */
  authToken?: string;
  /**
   * The signature produced by signing the payload (without pubKey field) using the user's private key.
   *
   * Sample signature: sign(keccak256(feature, authToken, timestamp))
   */
  signature: string;
  /**
   * The item id to be used for fetching the secret data.
   */
  itemId?: string;
};

/**
 * Payload structure for acquiring/releasing a lock on the metadata
 */
export type IMetadataLockRequestBody = {
  /**
   * The public key of the user
   */
  key: string;
  /**
   * The Unix timestamp when the request payload is created along with the signature.
   *
   */
  data: {
    timestamp: number;
  };
  /**
   * The signature produced by signing the payload (without pubKey field) using the user's private key.
   *
   * Sample signature: sign(keccak256(feature, authToken, timestamp))
   */
  signature: string;
  /**
   * The lock id to be released.
   */
  id?: string | undefined;
};

/**
 * FetchMetadataAccessCreds - The function to fetch the metadata access credentials.
 *
 * @returns The metadata access credentials.
 */
export type FetchMetadataAccessCreds = () => Promise<{
  metadataAccessToken: string;
}>;
