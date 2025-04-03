/**
 * SEC1 encoded public key
 * Format: 0x04 || x || y
 * Where x and y are 32-byte coordinates in big-endian format
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
  privKey: bigint;
  pubKey: SEC1EncodedPublicKey;
};

export type AuthenticateParams = {
  // for now we only support one idToken, in future we will support multiple to remove commitment call
  // so leaving it as an array for future use
  idTokens: string[];
  verifier: string;
  verifierID: string;
};

export type NodeAuthToken = {
  authToken: string;
  nodeIndex: number;
  nodePubKey: string;
};

/**
 * nodeAuthToken - The token issued by the node on verifying the idToken.
 *
 * nodeIndex - The index of the node that issued the token
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
 * keyPair - The encryption/decryption key pair which is used to encrypt/decrypt the secret data.
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
export type StoreSecretDataParams = {
  /**
   * The node auth tokens issued by the nodes on authenticating the user.
   */
  nodeAuthTokens: NodeAuthTokens;

  /**
   * The secret data to be stored.
   */
  secretData: string;

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
export type FetchSecretDataParams = {
  /**
   * The node auth tokens issued by the nodes on authenticating the user.
   */
  nodeAuthTokens: NodeAuthTokens;

  /**
   * The encryption key to be used to decrypt the secret data.
   */
  encKey: Uint8Array;

  /**
   * The authentication key to be used to provide valid signature for fetching the secret data.
   */
  authKeyPair: KeyPair;
};

/**
 * secretData - The secret data in decrypted form.
 */
export type FetchSecretDataResult = {
  secretData: string[];
};

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
  storeSecretData: (params: StoreSecretDataParams) => Promise<void>;

  /**
   * This function decrypts the secret data using the encryption key and returns the decrypted secret data.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.keyPair - The encryption/decryption key pair which is used to decrypt the secret data.
   *
   * @returns {FetchSecretDataResult} A promise that resolves with the decrypted secret data. Null if no secret data is found.
   */
  fetchSecretData: (
    params: FetchSecretDataParams,
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
   * The authentication token of the user issued by the SSS services
   */
  authToken: string;
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
 * Payload structure for storing secret data
 */
export type IBaseSetSecretDataRequestBody<T> = IBaseMetadataRequestBody & {
  /**
   * The secret data to be stored
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
 * The array of secret data to be stored in batch request
 */
export type IBatchSetData = {
  data: string;
  version?: string;
}[];

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
