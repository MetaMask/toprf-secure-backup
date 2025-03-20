/**
 * EncKeyPublic - The encryption public key.
 *
 * encPubKeyX - The encrypted public key X coordinate in hex format.
 *
 * encPubKeyY - The encrypted public key Y coordinate in hex format.
 */
export type EncKeyPublic = {
  encPubKeyX: string;
  encPubKeyY: string;
};

/**
 * EncKey - The encryption/decryption private and public key pair.
 *
 * encPrivKey - The encrypted private key in hex format.
 *
 * encPubKey - The encrypted public key.
 */
export type EncKey = {
  encPrivKey: `0x${string}`;
  encPubKey: EncKeyPublic;
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
 * [existingEncKeyPublicData] -  Existing encryption key public data.
 *
 * existingEncKeyPublicData.pubKeyX - The X coordinate of the encryption public key.
 *
 * existingEncKeyPublicData.pubKeyY - The Y coordinate of the encryption public key.
 *
 * existingEncKeyPublicData.keyIndex - The index of the encryption key.
 *
 * hasValidEncKey - Indicates whether a valid encryption key exists.
 */
export type AuthenticateResult = {
  nodeAuthTokens: NodeAuthTokens;
  existingEncKeyPublicData: {
    pubKeyX: string;
    pubKeyY: string;
    keyIndex: number;
  };
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

/**
 * encPubKey - The encryption public key of the user.
 */
export type FetchEncryptedSecretDataParams = {
  encPubKey: EncKeyPublic;
};

/**
 * encryptedSecretData - The encrypted secret data array in hex format.
 */
export type FetchEncryptedSecretDataResult = {
  encryptedSecretData: string[];
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
   * Update the encryption key
   *
   * @param params - The parameters for updating the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.newPassword - The new password of the user.
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

  /**
   * This function fetches the encrypted secret data from the nodes metadata store without decrypting it.
   *
   * @param params - The parameters for fetching the encrypted secret data.
   * @param params.encPubKey - The encryption public key of the user.
   *
   * @returns {FetchEncryptedSecretDataResult} A promise that resolves with the encrypted secret data.
   */
  fetchEncryptedSecretData: (
    params: FetchEncryptedSecretDataParams,
  ) => Promise<FetchEncryptedSecretDataResult>;
};
