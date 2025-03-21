/**
 * SEC1 encoded public key
 * Format: 0x04 || x || y
 * Where x and y are 32-byte coordinates in big-endian format
 */
export type SEC1EncodedPublicKey = string;

/**
 * EncKey - The encryption/decryption private and public key pair.
 *
 * encPrivKey - The decryption private key in Uint8Array format.
 *
 * encPubKey - The encryption public key in SEC1 encoded format.
 */
export type EncKey = {
  encPrivKey: Uint8Array;
  encPubKey: SEC1EncodedPublicKey;
};

export type AuthenticateParams = {
  // for now we only support one idToken, in future we will support multiple to remove commitment call
  // so leaving it as an array for future use
  idTokens: string[];
  endpoints: string[];
  indexes: number[];
  verifier: string;
  verifierID: string;
};

/**
 * nodeAuthToken - The token issued by the node on verifying the idToken.
 *
 * nodeIndex - The index of the node that issued the token
 */
export type NodeAuthTokens = {
  nodeAuthToken: string;
  nodeIndex: number;
}[];

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
 * nodeAuthTokens - The tokens issued by the nodes on verifying the idTokens.
 *
 * password - The password of the user.
 */
export type CreateEncKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  password: string;
};

/**
 * encKey - The encryption key which is used to encrypt/decrypt the secret data.
 */
export type CreateEncKeyResult = {
  encKey: EncKey;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * encKey - The encryption key which is used to encrypt the secret data before storing it.
 *
 * secretData - The secret data to be registered.
 */
export type StoreSecretDataParams = {
  nodeAuthTokens: NodeAuthTokens;
  encKey: EncKey;
  secretData: string;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * password - The password of the user.
 */
export type RecoverEncKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  password: string;
};

/**
 * encKey - The encryption key which is used to decrypt the secret data.
 */
export type RecoverEncKeyResult = {
  encKey: EncKey;
};

/**
 * nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
 *
 * newPassword - The new password of the user.
 *
 * encKey - The current encryption key of the user.
 */
export type UpdateEncKeyParams = {
  nodeAuthTokens: NodeAuthTokens;
  newPassword: string;
  encKey: EncKey;
};

/**
 * encKey - The new encryption key which is used to decrypt the secret data.
 */
export type UpdateEncKeyResult = {
  encKey: EncKey;
};

/**
 * encKey - The encryption key which is used to decrypt the secret data.
 */
export type FetchSecretDataParams = {
  encKey: EncKey;
};

/**
 * secretData - The secret data in decrypted form.
 */
export type FetchSecretDataResult = {
  secretData: string;
};

export type IMetamaskTOPRFAuth = {
  /**
   * This function is used to authenticate the user by sending the oauth idToken to the nodes and
   * getting the authentication tokens from the nodes in return.
   *
   * @param {AuthenticateParams} params - The authentication parameters.
   * @param {string[]} params.idTokens - An array of ID tokens for authentication.
   * @param {string[]} params.endpoints - The endpoints of the nodes to send the idToken to.
   * @param {number[]} params.indexes - The indexes of the nodes to send the idToken to.
   * @param {string} params.verifier - The verifier who issued the idToken.
   * @param {string} params.verifierID - The verifierID/userID assigned to the user by the verifier.
   *
   * @returns {AuthenticateResult} A promise that resolves with the authentication result.
   * @throws {Error} If idToken is older than 6 minutes.
   */
  authenticate: (params: AuthenticateParams) => Promise<AuthenticateResult>;

  /**
   * This function creates the encryption key which is used to encrypt/decrypt the secret data.
   *
   * @param params - The parameters for creating the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - New password of the user.
   *
   * @returns {CreateEncKeyResult} A promise that resolves with the encryption key.
   */
  createEncKey: (params: CreateEncKeyParams) => Promise<CreateEncKeyResult>;

  /**
   * This function recovers the encryption key which is used to decrypt the secret data.
   *
   * @param params - The parameters for recovering the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - The password of the user.
   *
   * @returns {RecoverEncKeyResult} A promise that resolves with the encryption key.
   */
  recoverEncKey: (params: RecoverEncKeyParams) => Promise<RecoverEncKeyResult>;

  /**
   * This function updates the encryption key and copies the secret data of existing encryption key to the new one.
   *
   * @param params - The parameters for updating the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.newPassword - The new password of the user.
   * @param params.encKey - The current encryption key of the user.
   *
   * @returns {UpdateEncKeyResult} A promise that resolves with the new encryption key.
   */
  updateEncKey: (params: UpdateEncKeyParams) => Promise<UpdateEncKeyResult>;

  /**
   * This function encrypts the secret data using the encryption key and stores it nodes metadata store in encrypted form.
   *
   * @param params - The parameters for registering new secret data.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.encKey - The encryption private and public key pair which is used to encrypt the secret data before storing it.
   * @param params.secretData - The array of secret data to be registered.
   *
   * @returns {void}
   */
  storeSecretData: (params: StoreSecretDataParams) => Promise<void>;

  /**
   * This function decrypts the secret data using the encryption key and returns the decrypted secret data.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.encKey - The encryption private and public key pair which is used to decrypt the secret data.
   *
   * @returns {FetchSecretDataResult} A promise that resolves with the decrypted secret data.
   */
  fetchSecretData: (
    params: FetchSecretDataParams,
  ) => Promise<FetchSecretDataResult>;
};
