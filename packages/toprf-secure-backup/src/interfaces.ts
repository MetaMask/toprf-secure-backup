/**
 * SEC1 encoded public key
 */
export type SEC1EncodedPublicKey = Uint8Array;

/**
 * KeyPair - The encryption/decryption private and public key pair.
 *
 * privKey - The decryption private key in bigint format.
 *
 * pubKey - The encryption public key in SEC1 encoded format.
 */
export type KeyPair = {
  sk: bigint;
  pk: SEC1EncodedPublicKey;
};

export type AuthenticateParams = {
  // for now we only support one idToken, in future we will support multiple to remove commitment call
  // so leaving it as an array for future use
  idTokens: string[];
  verifier: string;
  verifierID: string;
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
 * hasValidEncKey - Indicates whether a valid encryption key exists.
 */
export type AuthenticateResult = {
  nodeAuthTokens: NodeAuthTokens;
  hasValidEncKey: boolean;
};

/**
 * CreateEncryptionKeyParams - The parameters for creating an encryption key.
 *
 * verifier - The verifier of the user.
 *
 * verifierId - The verifier ID of the user.
 *
 * nodeAuthTokens - The tokens issued by the nodes on verifying the idTokens.
 *
 * password - The password of the user.
 */
export type CreateLocalEncryptionKeyParams = {
  password: string;
};

/**
 * CreateEncryptionKeyResult - The result of creating an encryption key.
 *
 * authKeyPair - The authentication key pair which is used to authenticate the user.
 *
 * encKey - The encryption key which is used to encrypt the secret data.
 */
export type CreateLocalEncryptionKeyResult = {
  oprfKey: bigint;
  seed: Uint8Array;
  authKeyPair: KeyPair;
  encKey: Uint8Array;
};

/**
 * CreateEncryptionKeyParams - The parameters for creating an encryption key.
 *
 * verifier - The verifier of the user.
 *
 * verifierId - The verifier ID of the user.
 *
 * nodeAuthTokens - The tokens issued by the nodes on verifying the idTokens.
 *
 * password - The password of the user.
 */
export type CreateEncryptionKeyParams = {
  verifier: string;
  verifierId: string;
  nodeAuthTokens: NodeAuthTokens;
  password: string;
};

/**
 * CreateEncryptionKeyResult - The result of creating an encryption key.
 *
 * authKeyPair - The authentication key pair which is used to authenticate the user.
 *
 * encKey - The encryption key which is used to encrypt the secret data.
 */
export type CreateEncryptionKeyResult = {
  authKeyPair: KeyPair;
  encKey: Uint8Array;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * keyPair - The encryption/decryption key pair which is used to encrypt the secret data before storing it.
 *
 * secretData - The secret data to be registered.
 */
export type AddSecretDataItemParams = {
  /**
   * The node auth tokens issued by the nodes on authenticating the user.
   */
  nodeAuthTokens: NodeAuthTokens;

  /**
   * The secret data to be stored.
   */
  secretData: Uint8Array;

  /**
   * The encryption key to be used to encrypt the secret data.
   */
  encKey: Uint8Array;

  /**
   * The authentication key to be used to provide valid signature for storing the secret data.
   */
  authKeyPair: KeyPair;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * password - The password of the user.
 */
export type RecoverEncryptionKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  password: string;
  verifier: string;
  verifierId: string;
};

/**
 * keyPair - The encryption/decryption key pair which is used to decrypt the secret data.
 */
export type RecoverEncryptionKeyResult = {
  authKeyPair: KeyPair;
  encKey: Uint8Array;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * newPassword - The new password of the user.
 *
 * keyPair - The current encryption key of the user.
 *
 */
export type ChangeEncryptionKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  newPassword: string;
  keyPair: KeyPair;
};

/**
 * keyPair - The new encryption/decryption key pair which is used to decrypt the secret data.
 */
export type ChangeEncryptionKeyResult = {
  keyPair: KeyPair;
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
 * Result from fetching the secret data from the metadata store.
 *
 * Uint8Array - The secret data in decrypted form.
 */
export type FetchSecretDataResult = Uint8Array[];

export type IToprfSecureBackup = {
  authenticate: (params: AuthenticateParams) => Promise<AuthenticateResult>;

  createEncKey: (
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
   * @returns {ChangeEncryptionKeyResult} A promise that resolves with the new encryption key.
   */
  changeEncKey: (
    params: ChangeEncryptionKeyParams,
  ) => Promise<ChangeEncryptionKeyResult>;

  /**
   * This function encrypts the secret data using the encryption key and stores it nodes metadata store in encrypted form.
   *
   * @param params - The parameters for registering new secret data.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.keyPair - The encryption/decryption key pair which is used to encrypt the secret data before storing it.
   * @param params.secretData - The array of secret data to be registered.
   *
   * @returns {void}
   */
  addSecretDataItem: (params: AddSecretDataItemParams) => Promise<void>;

  /**
   * This function fetches all secret data items associated with the given
   * auth pub key, decrypts, and returns them.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.decKey - The decryption key to be used to decrypt the secret data.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for fetching the secret data.
   *
   * @returns {FetchSecretDataResult} A promise that resolves with the decrypted secret data. Null if no secret data is found.
   */
  fetchAllSecretDataItems: (
    params: FetchAllSecretDataParams,
  ) => Promise<FetchSecretDataResult | null>;
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
export type IBatchSetData = {
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
export type IBaseSetSecretDataRequestBody<T> = IBaseMetadataRequestBody & {
  /**
   * The authentication token of the user issued by the SSS services
   */
  // authToken: string;
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
   * For storing the batch of secret data, the data should be an array of `IBatchSetData`.
   *
   * @example
   * ```ts
   * const data = [
   *   { data: Buffer.from('SECRET_DATA_1').toString('base64') },
   *   { data: Buffer.from('SECRET_DATA_2').toString('base64') },
   * ];
   * ```
   */
  data: T;
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
export type ISetSecretDataRequestBody =
  IBaseSetSecretDataRequestBody<string> & {
    /**
     * The version of the secret data
     */
    version?: string;
  };

/**
 * Payload structure for storing secret data in batch request
 */
export type IBatchSetSecretDataRequestBody =
  IBaseSetSecretDataRequestBody<IBatchSetData>;

/**
 * Payload structure for fetching secret data
 */
export type IGetSecretDataRequestBody = IBaseMetadataRequestBody & {
  /**
   * The signature produced by signing the payload (without pubKey field) using the user's private key.
   *
   * Sample signature: sign(keccak256(feature, authToken, timestamp))
   */
  signature: string;
};
