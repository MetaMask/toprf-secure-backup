/**
 * SEC1 encoded public key
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
export type StoreSecretDataParams = {
  nodeAuthTokens: NodeAuthTokens;
  keyPair: KeyPair;
  secretData: string;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * password - The password of the user.
 */
export type RecoverEncryptionKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  password: string;
};

/**
 * keyPair - The encryption/decryption key pair which is used to decrypt the secret data.
 */
export type RecoverEncryptionKeyResult = {
  keyPair: KeyPair;
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
  keyPair: KeyPair;
};

/**
 * secretData - The secret data in decrypted form.
 */
export type FetchSecretDataResult = {
  secretData: string;
};

export type IToprfSecureBackup = {
  authenticate: (params: AuthenticateParams) => Promise<AuthenticateResult>;

  createEncKey: (
    params: CreateEncryptionKeyParams,
  ) => Promise<CreateEncryptionKeyResult>;

  /**
   * This function recovers the encryption key which is used to decrypt the secret data.
   *
   * @param params - The parameters for recovering the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - The password of the user.
   *
   * @returns {RecoverEncryptionKeyResult} A promise that resolves with the encryption key.
   */
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
   * @returns {FetchSecretDataResult} A promise that resolves with the decrypted secret data.
   */
  fetchSecretData: (
    params: FetchSecretDataParams,
  ) => Promise<FetchSecretDataResult>;
};
