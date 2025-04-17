import { utf8ToBytes } from '@noble/curves/abstract/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import type {
  INodePub,
  TORUS_SAPPHIRE_NETWORK_TYPE,
} from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { FIRST_KEY_INDEX } from './constants';
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
  CreateLocalEncKeyResult,
  CreateLocalEncKeyParams,
  PersistOprfKeyParams,
  ChangeEncryptionKeyParams,
  ChangeEncryptionKeyResult,
  FetchAuthPubKeyParams,
  FetchAuthPubKeyResult,
  BatchAddSecretDataItemParams,
} from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataStore } from './metadata';
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

  #metadataStoreCache: MetadataStore | undefined;

  /**
   *
   * @param params - The parameters for the constructor.
   * @param params.network - The web3auth network to be used for key management and authentication.
   */
  constructor(params: { network: TORUS_SAPPHIRE_NETWORK_TYPE }) {
    this.#nodeDetailManager = new NodeDetailManager({
      network: params.network,
    });
  }

  /**
   * This function is used to authenticate the user by sending the oauth idToken to the nodes and
   * getting the authentication tokens from the nodes in return.
   *
   * @param params - The authentication parameters.
   * @param params.idTokens - An array of ID tokens for authentication.
   * @param params.verifier - The verifier who issued the idToken.
   * @param params.verifierId - The verifierId/userID assigned to the user by the verifier.
   * @param params.singleIdVerifierParams - Optional singleIdVerifierParams to be used for the authenticate request.
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
    const sessionPrivKey = secp256k1.utils.randomPrivateKey();
    const sessionPubKey =
      secp256k1.ProjectivePoint.fromPrivateKey(sessionPrivKey);
    const sessionPubKeyX = sessionPubKey.x.toString(16);
    const sessionPubKeyY = sessionPubKey.y.toString(16);

    // commit idToken to nodes
    const commitmentResults = await commitIdToken({
      idToken: params.idTokens[0],
      verifier: params.verifier,
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
      verifier: params.verifier,
      verifierId: params.verifierId,
      sessionPrivateKey: sessionPrivKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
      singleIdVerifierParams: params.singleIdVerifierParams,
    });
    return {
      nodeAuthTokens: authTokensData.map((tokenData) => ({
        authToken: tokenData.authToken,
        nodeIndex: tokenData.nodeIndex,
        nodePubKey: tokenData.nodePubKey,
      })),
      isNewUser,
    };
  }

  /**
   * This function locally creates an OPRF key without storing it at the key
   * management service. It returns the OPRF key, derives the corresponding key
   * seed, authentication key pair and encryption key.
   *
   * @param params - The parameters for creating the encryption key.
   * @param params.password - New password of the user.
   * @param params.oprfKey - Optional OPRF key to be used for the OPRF evaluation.
   *
   * @returns The OPRF key, seed, and derived keys.
   */
  createLocalEncKey(params: CreateLocalEncKeyParams): CreateLocalEncKeyResult {
    const { password, oprfKey = generateRandomScalar() } = params;
    const pwBytes = utf8ToBytes(password);
    const seed = OPRF.localEval(oprfKey, pwBytes);
    const authKeyPair = deriveAuthenticationKeyPair(seed);
    const encKey = deriveEncryptionKey(seed);

    return {
      oprfKey,
      seed,
      authKeyPair: {
        sk: authKeyPair.sk,
        pk: authKeyPair.pk,
      },
      encKey,
    };
  }

  /**
   * This function persists the OPRF key's shares at the servers.
   *
   * @param params - The parameters for persisting the OPRF key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.oprfKey - The OPRF key to be persisted.
   * @param params.authPubKey - The authentication public key.
   * @param params.verifier - The verifier name used for authentication.
   * @param params.verifierId - The verifierId/userID of the user.
   * @param params.shareKeyIndex - The share key index to be persisted. Required only during key change, defaults to FIRST_KEY_INDEX for first-time storage.
   * @param params.oldAuthKeyPair - The old authentication key pair of the user. Required only during key change, not needed for first-time storage.
   */
  async persistOprfKey(params: PersistOprfKeyParams): Promise<void> {
    const {
      nodeAuthTokens,
      oprfKey,
      authPubKey,
      verifier,
      verifierId,
      shareKeyIndex = FIRST_KEY_INDEX,
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
        verifier,
        verifierId,
        authTokens: nodeAuthTokens,
        shareKeyIndex,
        newOprfKey: oprfKey,
        newAuthPubKey: authPubKey,
        oldAuthPrivKey: oldAuthKeyPair.sk,
      });
    } else {
      await storeKeyShares({
        nodeEndpointsMap: selectedEndpointsMap,
        verifier,
        verifierId,
        authTokens: nodeAuthTokens,
        shareKeyIndex,
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
  async createEncKey(
    params: CreateEncryptionKeyParams,
  ): Promise<CreateEncryptionKeyResult> {
    const { nodeAuthTokens, password, verifier, verifierId } = params;
    const { oprfKey, authKeyPair, encKey } = this.createLocalEncKey({
      password,
    });

    await this.persistOprfKey({
      nodeAuthTokens,
      oprfKey,
      authPubKey: authKeyPair.pk,
      verifier,
      verifierId,
    });

    return {
      authKeyPair: {
        sk: authKeyPair.sk,
        pk: authKeyPair.pk,
      },
      encKey,
    };
  }

  /**
   * This function recovers the encryption key which is used to decrypt the secret data.
   *
   * @param params - The parameters for recovering the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - The password of the user.
   * @param params.verifier - The verifier name used for authentication.
   * @param params.verifierId - The verifierId/userID of the user.
   *
   * @returns The encryption key result with auth key pair, encryption key and share key index.
   */
  async recoverEncKey(
    params: RecoverEncryptionKeyParams,
  ): Promise<RecoverEncryptionKeyResult> {
    const { nodeAuthTokens, password, verifier, verifierId } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const pwBytes = utf8ToBytes(password);

    const { seed, shareKeyIndex } = await recoverTOPRFSeed({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      verifier,
      verifierId,
      userInput: pwBytes,
    });

    const authKeyPair = deriveAuthenticationKeyPair(seed);
    const encKeyPair = deriveEncryptionKey(seed);
    const rateLimitResetResult = new Promise<void>((resolve, reject) => {
      resetRateLimits({
        authTokens: nodeAuthTokens,
        nodeEndpointsMap,
        verifier,
        verifierId,
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
      authKeyPair: {
        sk: authKeyPair.sk,
        pk: authKeyPair.pk,
      },
      encKey: encKeyPair,
      shareKeyIndex,
      rateLimitResetResult,
    };
  }

  /**
   * This function replaces the existing encryption key with a new one by generating a new key from
   * the new password, copying all existing secret data encrypted with the old key to be encrypted
   * with the new key, and updating the key shares on the nodes.
   *
   * @param params - The parameters for changing the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.verifier - The verifier name used for authentication.
   * @param params.verifierId - The verifierId/userID of the user.
   * @param params.oldEncKey - The old encryption key of the user.
   * @param params.oldAuthKeyPair - The old authentication key pair of the user.
   * @param params.newPassword - The new password of the user.
   * @param params.newShareKeyIndex - The share key index to be used for the new key.
   *
   * @returns The new key pair and encryption key.
   */
  async changeEncKey(
    params: ChangeEncryptionKeyParams,
  ): Promise<ChangeEncryptionKeyResult> {
    const {
      nodeAuthTokens,
      verifier,
      verifierId,
      oldEncKey,
      oldAuthKeyPair,
      newPassword,
      newShareKeyIndex,
    } = params;

    const { oprfKey, authKeyPair, encKey } = this.createLocalEncKey({
      password: newPassword,
    });

    let metadataStore: MetadataStore | undefined;
    let oldMetadataLockId: string | undefined;
    let newMetadataLockId: string | undefined;

    try {
      metadataStore = await this.#createMetadataStore();

      [oldMetadataLockId, newMetadataLockId] = await Promise.all([
        metadataStore.acquireMetadataLock(oldAuthKeyPair),
        metadataStore.acquireMetadataLock(authKeyPair),
      ]);

      const existingData = await metadataStore.fetchAllSecretDataItems(
        oldEncKey,
        oldAuthKeyPair,
      );

      // Validate that this is actually a key change scenario
      if (!existingData || existingData.length === 0) {
        throw new Error('No existing data found to change key');
      }

      await metadataStore.batchAddSecretData({
        secretData: existingData,
        encKey,
        authKeyPair,
      });

      await this.persistOprfKey({
        nodeAuthTokens,
        oprfKey,
        authPubKey: authKeyPair.pk,
        verifier,
        verifierId,
        shareKeyIndex: newShareKeyIndex,
        oldAuthKeyPair,
      });

      return { authKeyPair, encKey };
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
    await metadataStore.addSecretDataItem(params);
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

      await metadataStore.batchAddSecretData(params);
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
    return metadataStore.fetchAllSecretDataItems(
      params.decKey,
      params.authKeyPair,
    );
  }

  /**
   * This function fetches the authentication public key.
   *
   * @param params - The parameters for getting the authentication public key.
   * @param params.authTokens - The auth tokens issued by the nodes on authenticating the user.
   * @param params.verifier - The verifier name used for authentication.
   * @param params.verifierId - The verifierId issued to user after authentication.
   *
   * @returns The authentication public key.
   */
  async fetchAuthPubKey(
    params: FetchAuthPubKeyParams,
  ): Promise<FetchAuthPubKeyResult> {
    const { nodeAuthTokens, verifier, verifierId } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const authPubKey = await getPubKey({
      authTokens: nodeAuthTokens,
      nodeEndpointsMap,
      verifier,
      verifierId,
    });
    return { authPubKey };
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
    const { torusNodeSSSEndpoints, torusIndexes, torusNodePub } =
      await this.#nodeDetailManager.getNodeDetails({
        verifier: 'DEFAULT_VERIFIER',
        verifierId: 'DEFAULT_VERIFIER_ID',
      });

    if (!torusNodeSSSEndpoints) {
      throw new Error('Failed to get node details');
    }

    return {
      nodeEndpoints: torusNodeSSSEndpoints,
      nodeEndpointsMap: createNodeEndpointsMap(
        torusNodeSSSEndpoints,
        torusIndexes,
      ),
      nodeIndexes: torusIndexes,
      nodePubkeys: torusNodePub,
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
    const metadataStore = new MetadataStore({
      metadataEndpoint: node1MetadataEndpoint,
    });

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
}
