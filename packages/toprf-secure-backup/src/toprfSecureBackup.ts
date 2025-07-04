import { keccak256AndHexify, remove0x } from '@metamask/auth-network-utils';
import { bytesToUtf8, equalBytes } from '@noble/ciphers/utils';
import { utf8ToBytes } from '@noble/curves/abstract/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type {
  INodePub,
  TORUS_SAPPHIRE_NETWORK_TYPE,
} from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import {
  FIRST_KEY_INDEX,
  MAX_PASSWORD_CHAIN_LENGTH,
  PW_BACKUP_ITEM_ID,
} from './constants';
import { TOPRFError } from './errors';
import { getPubKey } from './getPubKeyRequest';
import type {
  AuthenticateParams,
  AuthenticateResult,
  CreateEncryptionKeyParams,
  CreateEncryptionKeyResult,
  FetchAllSecretDataParams,
  IToprfSecureBackup,
  RecoverEncryptionKeyParams,
  RecoverEncryptionKeyResult,
  AddSecretDataItemParams,
  ChangeEncryptionKeyParams,
  ChangeEncryptionKeyResult,
  FetchAuthPubKeyParams,
  FetchAuthPubKeyResult,
  PersistLocalKeyParams,
  CreateLocalKeyParams,
  CreateLocalKeyResult,
  BatchAddSecretDataItemParams,
  RecoverPwEncKeyParams,
  KeyPair,
  RecoverPwEncKeyResult,
  NodeDetailsOverride,
} from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
  derivePwEncKey,
} from './keyDerivation';
import type { SecretDataItem } from './metadata';
import { MetadataStore } from './metadata';
import type { FetchMetadataAccessCreds, KeyDeriver } from './oprf';
import { OPRF, generateRandomScalar } from './oprf';
import { resetRateLimits } from './resetRateLimits';
import { storeKeyShares, changeKeyShares } from './storeSharesRequest';
import { recoverTOPRFSeed } from './toprfEvalRequest';
import { createNodeEndpointsMap } from './utils';

/**
 * ToprfSecureBackup - The main class for the tOPRF Secure Backup service.
 *
 */
export class ToprfSecureBackup implements IToprfSecureBackup {
  readonly #nodeDetailManager: NodeDetailManager;

  readonly #nodeDetailsOverride?: NodeDetailsOverride;

  readonly #keyDeriver?: KeyDeriver;

  readonly #fetchMetadataAccessCreds: FetchMetadataAccessCreds;

  #metadataStoreCache: MetadataStore | undefined;

  /**
   * The constructor for the ToprfSecureBackup class.
   *
   * If `keyDeriver` is provided, it will be used as an additional step during
   * key derivation. This can be used, for example, to inject a slow key
   * derivation step to protect against local brute force attacks on the
   * password.
   *
   * @param params - The parameters for the constructor.
   * @param params.network - The web3auth network to be used for key management
   * and authentication.
   * @param params.nodeDetailsOverride - Optional overrides for node details
   * like SSS endpoints, indexes, and public keys.
   * @param params.keyDeriver - Optional key deriver to be used for an
   * additional layer of security.
   * @param params.fetchMetadataAccessCreds - Optional function to fetch metadata access credentials.
   */
  constructor(params: {
    network: TORUS_SAPPHIRE_NETWORK_TYPE;
    fetchMetadataAccessCreds: FetchMetadataAccessCreds;
    nodeDetailsOverride?: NodeDetailsOverride;
    keyDeriver?: KeyDeriver;
  }) {
    this.#nodeDetailManager = new NodeDetailManager({
      network: params.network,
    });
    this.#nodeDetailsOverride = params.nodeDetailsOverride;
    this.#keyDeriver = params.keyDeriver;
    this.#fetchMetadataAccessCreds = params.fetchMetadataAccessCreds;
  }

  /**
   * This function is used to authenticate the user by sending the oauth idToken to the nodes and
   * getting the authentication tokens from the nodes in return.
   *
   * @param params - The authentication parameters.
   * @param params.idTokens - An array of id tokens for authentication.
   * @param params.authConnectionId - The auth connection name to be used for the authenticate request
   * @param params.userId - The user id of the user issued by authentication service
   * @param params.groupedAuthConnectionParams - Optional groupedAuthConnectionParams to be used for the authenticate request.
   * You can pass this to use aggregate verifier.
   *
   * @returns - The authentication result containing the authentication tokens and a boolean indicating if the user is new or not.
   * isNewUser - Indicates if the user has completed the key setup process or not.
   * if `true` then the user hasn't completed the social + password setup process.
   * if `false` then the user has completed the social + password setup process.
   * @throws {Error} If idToken is older than 6 minutes.
   */
  async authenticate(params: AuthenticateParams): Promise<AuthenticateResult> {
    const { nodeEndpoints, nodeEndpointsMap } = await this.#getNodeDetails();
    let sessionPrivKey: Uint8Array | null = secp256k1.utils.randomPrivateKey();

    try {
      const sessionPubKey =
        secp256k1.ProjectivePoint.fromPrivateKey(sessionPrivKey);
      const sessionPubKeyX = sessionPubKey.x.toString(16);
      const sessionPubKeyY = sessionPubKey.y.toString(16);

      let hashedIdToken: string | undefined;
      if (params.groupedAuthConnectionId) {
        // if groupedAuthConnectionId is provided, we'll compute the hashedIdToken for the aggregate (single id) verifier login
        hashedIdToken = remove0x(
          keccak256AndHexify(Buffer.from(params.idTokens[0], 'utf8')),
        );
      }

      // commit idToken to nodes
      const commitmentResults = await commitIdToken({
        idToken: hashedIdToken ?? params.idTokens[0],
        authConnectionId:
          params.groupedAuthConnectionId ?? params.authConnectionId,
        sessionPubKeyX,
        sessionPubKeyY,
        endpoints: nodeEndpoints,
      });

      // use only the node indexes that returned valid commitment responses
      const selectedEndpointsMap = commitmentResults.reduce<
        Record<number, string>
      >((acc, result) => {
        acc[result.nodeIndex] = nodeEndpointsMap[result.nodeIndex];
        return acc;
      }, {});

      // get auth tokens from nodes
      const { authTokensData, isNewUser } = await authenticateUser({
        idToken: params.idTokens[0],
        authConnectionId: params.authConnectionId,
        userId: params.userId,
        sessionPrivateKey: sessionPrivKey,
        nodeEndpointsMap: selectedEndpointsMap,
        commitmentSignatures: commitmentResults,
        groupedAuthConnectionId: params.groupedAuthConnectionId,
        hashedIdToken,
      });

      return {
        nodeAuthTokens: authTokensData.map((tokenData) => ({
          authToken: tokenData.authToken,
          nodeIndex: tokenData.nodeIndex,
          nodePubKey: tokenData.nodePubKey,
        })),
        isNewUser,
      };
    } finally {
      // Clean up session private key
      sessionPrivKey.fill(0);
      sessionPrivKey = null;
    }
  }

  /**
   * This function locally creates an OPRF and encryption keys without storing them at the
   * key management service. It returns the OPRF key, derives the corresponding key seed,
   * authentication key pair and encryption key.
   *
   * @param params - The parameters for creating the encryption key.
   * @param params.password - New password of the user.
   * @param params.oprfKey - Optional OPRF key to be used for the OPRF evaluation.
   *
   * @returns The OPRF key, seed, and derived keys.
   */
  async createLocalKey(
    params: CreateLocalKeyParams,
  ): Promise<CreateLocalKeyResult> {
    const { password, oprfKey = generateRandomScalar() } = params;
    let pwBytes: Uint8Array | null = null;

    try {
      pwBytes = utf8ToBytes(password);
      const seed = await OPRF.localEval(oprfKey, pwBytes, this.#keyDeriver);

      const authKeyPair = deriveAuthenticationKeyPair(seed);
      const encKey = deriveEncryptionKey(seed);
      const pwEncKey = derivePwEncKey(seed);

      return {
        oprfKey,
        seed,
        authKeyPair,
        encKey,
        pwEncKey,
      };
    } finally {
      // Clean up sensitive intermediate data
      if (pwBytes) {
        pwBytes.fill(0);
        pwBytes = null;
      }
    }
  }

  /**
   * This function persists the OPRF key's shares at the servers.
   *
   * @param params - The parameters for persisting the OPRF key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.oprfKey - The OPRF key to be persisted.
   * @param params.authPubKey - The authentication public key.
   * @param params.authConnectionId - The auth connection name used for authentication.
   * @param params.groupedAuthConnectionId - An optional grouped auth connection name used for authentication with aggregate (single id) verifier.
   * @param params.userId - The user id of the user issued by authentication service.
   * @param params.keyShareIndex - The key share index to be persisted. Required only during key change, defaults to FIRST_KEY_INDEX for first-time storage.
   * @param params.oldAuthKeyPair - The old authentication key pair of the user. Required only during key change, not needed for first-time storage.
   */
  async persistLocalKey(params: PersistLocalKeyParams): Promise<void> {
    const {
      nodeAuthTokens,
      oprfKey,
      authPubKey,
      authConnectionId,
      groupedAuthConnectionId,
      userId,
      keyShareIndex = FIRST_KEY_INDEX,
      oldAuthKeyPair,
    } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();

    const selectedEndpointsMap = nodeAuthTokens.reduce<Record<number, string>>(
      (acc, tokenData) => {
        acc[tokenData.nodeIndex] = nodeEndpointsMap[tokenData.nodeIndex];
        return acc;
      },
      {},
    );

    if (oldAuthKeyPair) {
      await changeKeyShares({
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        groupedAuthConnectionId,
        userId,
        authTokens: nodeAuthTokens,
        keyShareIndex,
        newOprfKey: oprfKey,
        newAuthPubKey: authPubKey,
        oldAuthPrivKey: oldAuthKeyPair.sk,
      });
    } else {
      await storeKeyShares({
        nodeEndpointsMap: selectedEndpointsMap,
        authConnectionId,
        groupedAuthConnectionId,
        userId,
        authTokens: nodeAuthTokens,
        keyShareIndex,
        oprfKey,
        authPubKey,
      });
    }
  }

  /**
   * This function creates the encryption key which is used to encrypt/decrypt the secret data.
   *
   * @param params - The parameters for creating the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - New password of the user.
   *
   * @returns The encryption key.
   */
  async createAndPersistEncKey(
    params: CreateEncryptionKeyParams,
  ): Promise<CreateEncryptionKeyResult> {
    const { nodeAuthTokens, password, authConnectionId, userId } = params;
    const { oprfKey, authKeyPair, encKey, pwEncKey } =
      await this.createLocalKey({
        password,
      });

    await this.persistLocalKey({
      nodeAuthTokens,
      oprfKey,
      authPubKey: authKeyPair.pk,
      authConnectionId,
      userId,
    });

    return {
      authKeyPair: {
        sk: authKeyPair.sk,
        pk: authKeyPair.pk,
      },
      encKey,
      pwEncKey,
    };
  }

  /**
   * This function recovers the encryption key which is used to decrypt the secret data.
   *
   * @param params - The parameters for recovering the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - The password of the user.
   * @param params.authConnectionId - The auth connection name used for authentication.
   * @param params.groupedAuthConnectionId - An optional grouped auth connection name used for authentication with aggregate (single id) verifier.
   * @param params.userId - The user id of the user.
   *
   * @returns The encryption key result with auth key pair, encryption key and key share index.
   */
  async recoverEncKey(
    params: RecoverEncryptionKeyParams,
  ): Promise<RecoverEncryptionKeyResult> {
    const {
      nodeAuthTokens,
      password,
      authConnectionId,
      groupedAuthConnectionId,
      userId,
    } = params;

    let pwBytes: Uint8Array | null = null;
    let seed: Uint8Array | null = null;

    try {
      const { nodeEndpointsMap } = await this.#getNodeDetails();
      pwBytes = utf8ToBytes(password);

      const { seed: seedValue, keyShareIndex } = await recoverTOPRFSeed({
        authTokens: nodeAuthTokens,
        nodeEndpointsMap,
        authConnectionId,
        groupedAuthConnectionId,
        userId,
        userInput: pwBytes,
        keyDeriver: this.#keyDeriver,
      });

      seed = seedValue;

      const authKeyPair = deriveAuthenticationKeyPair(seed);
      const encKey = deriveEncryptionKey(seed);
      const pwEncKey = derivePwEncKey(seed);

      const rateLimitResetResult = new Promise<void>((resolve, reject) => {
        resetRateLimits({
          authTokens: nodeAuthTokens,
          nodeEndpointsMap,
          authConnectionId,
          groupedAuthConnectionId,
          userId,
          authPrivKey: authKeyPair.sk,
        })
          .then(() => {
            return resolve();
          })
          .catch((error) => {
            reject(error as Error);
          });
      });

      return {
        authKeyPair,
        encKey,
        pwEncKey,
        keyShareIndex,
        rateLimitResetResult,
      };
    } finally {
      // Clean up sensitive intermediate data
      if (pwBytes) {
        pwBytes.fill(0);
        pwBytes = null;
      }

      if (seed) {
        seed.fill(0);
        seed = null;
      }
    }
  }

  /**
   * This function replaces the existing encryption key with a new one by generating a new key from
   * the new password, copying all existing secret data encrypted with the old key to be encrypted
   * with the new key, and updating the key shares on the nodes.
   *
   * @param params - The parameters for changing the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.authConnectionId - The auth connection name used for authentication.
   * @param params.groupedAuthConnectionId - An optional grouped auth connection name used for authentication with aggregate (single id) verifier.
   * @param params.userId - The user id of the user.
   * @param params.oldEncKey - The old encryption key of the user.
   * @param params.oldAuthKeyPair - The old authentication key pair of the user.
   * @param params.newKeyShareIndex - The key share index to be used for the new key.
   * @param params.newPassword - Optional new password of the user, either this or pregeneratedOprfKey is required.
   * @param params.pregeneratedOprfKey - Optional pregenerated OPRF key to be used for the key change, if not provided, a new key will be generated from the new password.
   *
   * @returns The new key pair and encryption key.
   * @throws {Error} If both newPassword and pregeneratedOprfKey are provided.
   * @throws {Error} If neither newPassword nor pregeneratedOprfKey is provided.
   */
  async changeEncKey(
    params: ChangeEncryptionKeyParams,
  ): Promise<ChangeEncryptionKeyResult> {
    const {
      nodeAuthTokens,
      authConnectionId,
      groupedAuthConnectionId,
      userId,
      oldEncKey,
      oldPwEncKey,
      oldAuthKeyPair,
      newPassword,
      newKeyShareIndex,
      pregeneratedOprfKey,
    } = params;

    if (!pregeneratedOprfKey && !newPassword) {
      throw new Error('Either newPassword or pregeneratedOprfKey is required');
    }

    if (pregeneratedOprfKey && newPassword) {
      throw new Error(
        'Only one of newPassword or pregeneratedOprfKey is allowed',
      );
    }

    // if newPassword is provided, create a new key from the password
    // else use the pregeneratedOprfKey, both can't be undefined as per check above.
    const { oprfKey, authKeyPair, encKey, pwEncKey } = newPassword
      ? await this.createLocalKey({ password: newPassword })
      : (pregeneratedOprfKey as CreateLocalKeyResult);

    let metadataStore: MetadataStore | undefined;
    let oldMetadataLockId: string | undefined;
    let newMetadataLockId: string | undefined;

    try {
      metadataStore = await this.#createMetadataStore();

      [oldMetadataLockId, newMetadataLockId] = await Promise.all([
        metadataStore.acquireMetadataLock(oldAuthKeyPair),
        metadataStore.acquireMetadataLock(authKeyPair),
      ]);

      const existingData = (
        await metadataStore.fetchAllSecretDataItems(oldEncKey, oldAuthKeyPair)
      ).map((dataItem) => ({ data: dataItem.data }));

      // Validate that this is actually a key change scenario
      if (!existingData || existingData.length === 0) {
        throw new Error('No existing data found to change key');
      }

      const pwBackup: SecretDataItem = {
        data: serializePwBackup('', oldPwEncKey, oldAuthKeyPair),
        itemId: PW_BACKUP_ITEM_ID,
      };

      const secretDataItems = [pwBackup, ...existingData];
      const encKeys = [pwEncKey, ...existingData.map(() => encKey)];
      await metadataStore.batchAddSecretData({
        secretData: secretDataItems,
        encKey: encKeys,
        authKeyPair,
      });

      await this.persistLocalKey({
        nodeAuthTokens,
        oprfKey,
        authPubKey: authKeyPair.pk,
        authConnectionId,
        groupedAuthConnectionId,
        userId,
        keyShareIndex: newKeyShareIndex,
        oldAuthKeyPair,
      });

      return { authKeyPair, encKey, pwEncKey };
    } finally {
      if (metadataStore && oldMetadataLockId && newMetadataLockId) {
        try {
          await Promise.all([
            metadataStore.releaseMetadataLock(
              oldAuthKeyPair,
              oldMetadataLockId,
            ),
            metadataStore.releaseMetadataLock(authKeyPair, newMetadataLockId),
          ]);
        } catch (error) {
          console.error('Failed to release metadata lock:', error);
        }
      }
    }
  }

  /**
   * This function encrypts the secret data using the encryption key and stores it nodes metadata store in encrypted form.
   *
   * @param params - The parameters for registering new secret data.
   * @param params.encKey - The encryption key which is used to encrypt the secret data before storing it.
   * @param params.secretData - The array of secret data to be registered.
   * @param params.authKeyPair - The authentication key pair which is used to authenticate the user to the storage service.
   */
  async addSecretDataItem(params: AddSecretDataItemParams): Promise<void> {
    const metadataStore = await this.#createMetadataStore();
    await metadataStore.addSecretDataItem({
      ...params,
      secretData: {
        data: params.secretData,
      },
    });
  }

  /**
   * This function encrypts the array of secret data using the encryption key and stores in the metadata store in encrypted form as a batch.
   *
   * @param params - The parameters for registering new secret data.
   * @param params.encKey - The encryption key to be used to encrypt the secret data before storing it.
   * @param params.secretData - The array of secret data to be stored.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for storing the secret data.
   */
  async batchAddSecretDataItems(
    params: BatchAddSecretDataItemParams,
  ): Promise<void> {
    const metadataStore = await this.#createMetadataStore();

    let metadataLockId: string | undefined;

    try {
      // acquire metadata lock
      metadataLockId = await metadataStore.acquireMetadataLock(
        params.authKeyPair,
      );

      await metadataStore.batchAddSecretData({
        ...params,
        secretData: params.secretData.map((data) => ({
          data,
        })),
      });
    } finally {
      // release metadata lock
      if (metadataLockId) {
        try {
          await metadataStore.releaseMetadataLock(
            params.authKeyPair,
            metadataLockId,
          );
        } catch (error) {
          console.error('Failed to release metadata lock:', error);
        }
      }
    }
  }

  /**
   * This function fetches all secret data items associated with the given
   * auth pub key, decrypts, and returns them.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.decKey - The decryption key to be used to decrypt the secret data.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for fetching the secret data.
   *
   * @returns The decrypted secret data. Returns an empty array if no secret data is found.
   */
  async fetchAllSecretDataItems(
    params: FetchAllSecretDataParams,
  ): Promise<Uint8Array[]> {
    const metadataStore = await this.#createMetadataStore();
    const dataItems = await metadataStore.fetchAllSecretDataItems(
      params.decKey,
      params.authKeyPair,
    );
    return dataItems.map((dataItem: SecretDataItem) => dataItem.data);
  }

  /**
   * This function fetches the authentication public key.
   *
   * @param params - The parameters for getting the authentication public key.
   * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
   * @param params.authConnectionId - The auth connection name used for authentication.
   * @param params.groupedAuthConnectionId - An optional grouped auth connection name used for authentication with aggregate (single id) verifier.
   * @param params.userId - The user id of the user.
   *
   * @returns The authentication public key.
   */
  async fetchAuthPubKey(
    params: FetchAuthPubKeyParams,
  ): Promise<FetchAuthPubKeyResult> {
    const {
      nodeAuthTokens,
      authConnectionId,
      userId,
      groupedAuthConnectionId,
    } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const authPubKey = await getPubKey({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      authConnectionId,
      userId,
      groupedAuthConnectionId,
    });
    return { authPubKey };
  }

  /**
   * This function looks up a password encryption key from the password
   * encryption key history.
   *
   * @param params - The parameters for getting the password encryption key.
   * @param params.targetPwPubKey - The target password public key.
   * @param params.curPwEncKey - The current password encryption key.
   * @param params.curAuthKeyPair - The current authentication key pair.
   * @param params.maxPwChainLength - Optional maximum password chain length
   * allowed to be traversed.
   *
   * @returns The password encryption key.
   */
  async recoverPwEncKey(
    params: RecoverPwEncKeyParams,
  ): Promise<RecoverPwEncKeyResult> {
    const {
      targetAuthPubKey: targetPwPubKey,
      curPwEncKey,
      curAuthKeyPair,
      maxPwChainLength = MAX_PASSWORD_CHAIN_LENGTH,
    } = params;

    let pwAndKeys = {
      password: '',
      encKey: curPwEncKey,
      authKeyPair: curAuthKeyPair,
    };

    for (let i = 0; i < maxPwChainLength; i++) {
      try {
        pwAndKeys = await this.#getPrevPasswordAndKeys({
          encKey: pwAndKeys.encKey,
          authKeyPair: pwAndKeys.authKeyPair,
        });
        if (equalBytes(pwAndKeys.authKeyPair.pk, targetPwPubKey)) {
          return { pwEncKey: pwAndKeys.encKey };
        }
      } catch (error) {
        throw TOPRFError.couldNotFetchPassword((error as Error).message);
      }
    }

    throw TOPRFError.couldNotFetchPassword(
      'Exceeded maximum password chain length',
    );
  }

  /**
   * Gets the node details.
   *
   * @returns The node details containing the node endpoints, indexes and pubkeys.
   */
  async #getNodeDetails(): Promise<{
    nodeEndpoints: string[];
    nodeEndpointsMap: Record<number, string>;
    nodeIndexes: number[];
    nodePubkeys: INodePub[];
  }> {
    let finalIndexes = this.#nodeDetailsOverride?.indexes;
    let finalPubKeys = this.#nodeDetailsOverride?.pubKeys;
    let finalEndpoints = this.#nodeDetailsOverride?.endpoints;

    if (finalIndexes && finalPubKeys && Array.isArray(finalEndpoints)) {
      ToprfSecureBackup.#validateNodeDetailsLengths(
        finalIndexes,
        finalPubKeys,
        finalEndpoints,
      );
      return {
        nodeEndpoints: finalEndpoints,
        nodeEndpointsMap: createNodeEndpointsMap(finalEndpoints, finalIndexes),
        nodeIndexes: finalIndexes,
        nodePubkeys: finalPubKeys,
      };
    }

    const { torusNodeSSSEndpoints, torusIndexes, torusNodePub } =
      await this.#nodeDetailManager.getNodeDetails({
        verifier: 'auth-connection-id',
        verifierId: 'user-id',
      });

    finalIndexes ??= torusIndexes;
    finalPubKeys ??= torusNodePub;

    if (!Array.isArray(finalEndpoints)) {
      if (!torusNodeSSSEndpoints) {
        const message = 'Failed to get node details';
        throw new Error(message);
      }

      finalEndpoints = finalEndpoints
        ? torusNodeSSSEndpoints.map((endpoint) => {
            const url = new URL(endpoint);
            url.pathname = finalEndpoints as string;
            return url.href;
          })
        : torusNodeSSSEndpoints;
    }

    ToprfSecureBackup.#validateNodeDetailsLengths(
      finalIndexes,
      finalPubKeys,
      finalEndpoints,
    );

    console.log('finalEndpoints', finalEndpoints);
    return {
      nodeEndpoints: finalEndpoints,
      nodeEndpointsMap: createNodeEndpointsMap(finalEndpoints, finalIndexes),
      nodeIndexes: finalIndexes,
      nodePubkeys: finalPubKeys,
    };
  }

  /**
   * Creates and caches the metadata store instance.
   *
   * @returns The metadata store.
   */
  async #createMetadataStore(): Promise<MetadataStore> {
    if (this.#metadataStoreCache) {
      return this.#metadataStoreCache;
    }

    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const metadataEndpointsMap =
      await this.#getMetadataEndpointsMap(nodeEndpointsMap);
    const node1MetadataEndpoint = metadataEndpointsMap['1'];
    const { accessToken, apiKey } = await this.#fetchMetadataAccessCreds();
    if (!accessToken && !apiKey) {
      throw new Error('No metadata access token or api key found');
    }

    const metadataStoreOptions = accessToken
      ? {
          metadataEndpoint: node1MetadataEndpoint,
          accessToken,
        }
      : { metadataEndpoint: node1MetadataEndpoint, apiKey: apiKey as string };

    const metadataStore = new MetadataStore(metadataStoreOptions);

    this.#metadataStoreCache = metadataStore;

    return metadataStore;
  }

  /**
   * Gets the metadata endpoints.
   *
   * @param nodeEndpointsMap - The node endpoints map.
   *
   * @returns The metadata endpoints map with node index as key and metadata endpoint as value.
   */
  async #getMetadataEndpointsMap(
    nodeEndpointsMap: Record<number, string>,
  ): Promise<{ [nodeIndex: string]: string }> {
    const metadataEndpointsMap: { [nodeIndex: string]: string } = {};
    Object.entries(nodeEndpointsMap).forEach(([key, value]) => {
      const url = new URL(value);
      metadataEndpointsMap[key] = `${url.origin}/metadata`;
    });
    return metadataEndpointsMap;
  }

  /**
   * Gets the previous password and keys.
   *
   * @param params - The parameters for getting the previous password and keys.
   * @param params.encKey - The encryption key to be used for decrypting the secret data.
   * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
   *
   * @returns The previous password and keys.
   */
  async #getPrevPasswordAndKeys(params: {
    encKey: Uint8Array;
    authKeyPair: KeyPair;
  }): Promise<{
    password: string;
    encKey: Uint8Array;
    authKeyPair: KeyPair;
  }> {
    const metadataStore = await this.#createMetadataStore();

    const pwBackupData = await metadataStore.fetchAllSecretDataItems(
      params.encKey,
      params.authKeyPair,
      PW_BACKUP_ITEM_ID,
    );

    if (pwBackupData.length === 0) {
      throw new Error('Failed to get previous password and keys');
    }

    // Parse JSON object.
    const pwBackupDataJson = deserializePwBackup(pwBackupData[0].data);

    return {
      password: pwBackupDataJson.pw,
      encKey: pwBackupDataJson.encKey,
      authKeyPair: pwBackupDataJson.authKeyPair,
    };
  }

  /**
   * Validates that the lengths of node detail arrays are consistent.
   *
   * @param indexes - Array of node indexes.
   * @param pubKeys - Array of node public keys.
   * @param endpoints - Array of SSS endpoint URLs.
   * @throws If lengths are inconsistent.
   */
  static #validateNodeDetailsLengths(
    indexes: unknown[],
    pubKeys: unknown[],
    endpoints: unknown[],
  ): void {
    if (
      indexes.length !== pubKeys.length ||
      indexes.length !== endpoints.length
    ) {
      const message =
        'Node details arrays (indexes, pubKeys, endpoints) must have equal lengths';
      throw new Error(message);
    }
  }
}

/**
 * Serializes the password, encryption key, and authentication key pair into a JSON string.
 *
 * @param pw - The password.
 * @param encKey - The encryption key.
 * @param authKeyPair - The authentication key pair.
 * @returns The serialized JSON string.
 */
function serializePwBackup(
  pw: string,
  encKey: Uint8Array,
  authKeyPair: KeyPair,
): Uint8Array {
  return utf8ToBytes(
    JSON.stringify({
      pw,
      encKey: bytesToHex(encKey),
      authKeyPair: {
        sk: authKeyPair.sk.toString(),
        pk: bytesToHex(authKeyPair.pk),
      },
    }),
  );
}

/**
 * Deserializes the password, encryption key, and authentication key pair from a JSON string.
 *
 * @param data - The serialized JSON string.
 * @returns The password, encryption key, and authentication key pair.
 */
function deserializePwBackup(data: Uint8Array): {
  pw: string;
  encKey: Uint8Array;
  authKeyPair: KeyPair;
} {
  const json = JSON.parse(bytesToUtf8(data));
  return {
    pw: json.pw,
    encKey: hexToBytes(json.encKey),
    authKeyPair: {
      sk: BigInt(json.authKeyPair.sk),
      pk: hexToBytes(json.authKeyPair.pk),
    },
  };
}
