import { thresholdSame } from '@metamask/auth-network-utils';
import { utf8ToBytes } from '@noble/curves/abstract/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import type {
  INodePub,
  TORUS_SAPPHIRE_NETWORK_TYPE,
} from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitIdToken } from './commitRequest';
import { EXISTING_USER_AUTHENTICATION_THRESHOLD } from './constants';
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
} from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataStore } from './metadata';
import { OPRF, generateRandomScalar } from './oprf';
import { resetRateLimits } from './resetRateLimits';
import { storeKeyShares } from './storeSharesRequest';
import { recoverTOPRFSeed } from './toprfEvalRequest';
import { createNodeEndpointsMap } from './utils';

/**
 *
 */
export class ToprfSecureBackup implements Partial<IToprfSecureBackup> {
  readonly #nodeDetailManager: NodeDetailManager;

  #metadataStoreCache: MetadataStore | undefined;

  /**
   *
   * @param params - The parameters for the constructor.
   * @param params.network - The web3auth network to be used key management and authentication.
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
   * @param params.verifierID - The verifierID/userID assigned to the user by the verifier.
   *
   * @returns A promise that resolves with the authentication result.
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
    const authTokens = await authenticateUser({
      idToken: params.idTokens[0],
      verifier: params.verifier,
      verifierID: params.verifierID,
      sessionPrivateKey: sessionPrivKey,
      nodeEndpointsMap: selectedEndpointsMap,
      commitmentSignatures: commitmentResults,
    });
    const hasValidEncKey = thresholdSame(
      authTokens.map((tokenData) => ({
        token: tokenData.authToken,
        keyIndex: tokenData.keyIndex,
      })),
      EXISTING_USER_AUTHENTICATION_THRESHOLD,
    );
    return {
      nodeAuthTokens: authTokens.map((tokenData) => ({
        authToken: tokenData.authToken,
        nodeIndex: tokenData.nodeIndex,
        nodePubKey: tokenData.nodePubKey,
      })),
      hasValidEncKey: Boolean(hasValidEncKey),
    };
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
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const oprfKey = generateRandomScalar();
    const pwBytes = utf8ToBytes(password);
    const seed = OPRF.localEval(oprfKey, pwBytes);
    const authKeyPair = deriveAuthenticationKeyPair(seed);
    const selectedEndpointsMap = nodeAuthTokens.reduce<Record<number, string>>(
      (acc, tokenData) => {
        acc[tokenData.nodeIndex] = nodeEndpointsMap[tokenData.nodeIndex];
        return acc;
      },
      {},
    );
    await storeKeyShares({
      nodeEndpointsMap: selectedEndpointsMap,
      verifier,
      verifierId,
      authTokens: nodeAuthTokens,
      keyIndex: 1,
      oprfKey,
      authPubKey: authKeyPair.pk,
    });
    const encKey = deriveEncryptionKey(seed);

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
   * @returns The encryption key.
   */
  async recoverEncKey(
    params: RecoverEncryptionKeyParams,
  ): Promise<RecoverEncryptionKeyResult> {
    const { nodeAuthTokens, password, verifier, verifierId } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const pwBytes = utf8ToBytes(password);
    const seed = await recoverTOPRFSeed({
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
      rateLimitResetResult,
    };
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

    if (!torusNodeSSSEndpoints || !torusIndexes || !torusNodePub) {
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
