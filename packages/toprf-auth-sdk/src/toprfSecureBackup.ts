import { getSecp256K1Curve, thresholdSame } from '@metamask/auth-network-utils';
import type {
  INodePub,
  TORUS_SAPPHIRE_NETWORK_TYPE,
} from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';
import { keccak256 } from 'ethereum-cryptography/keccak';

import { authenticateUser } from './authenticateRequest';
import { commitmentRequest } from './commitmentRequest';
import type {
  AuthenticateParams,
  AuthenticateResult,
  CreateEncryptionKeyParams,
  CreateEncryptionKeyResult,
  FetchSecretDataParams,
  FetchSecretDataResult,
  IToprfSecureBackup,
  NodeAuthTokens,
  RecoverEncryptionKeyParams,
  RecoverEncryptionKeyResult,
  StoreSecretDataParams,
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

/**
 *
 */
export class ToprfSecureBackup implements Partial<IToprfSecureBackup> {
  readonly #nodeDetailManager: NodeDetailManager;

  /**
   *
   * @param params - The parameters for the constructor.
   * @param params.network - The web3auth network to be used key management and authentication.
   */
  constructor(params: { network: TORUS_SAPPHIRE_NETWORK_TYPE }) {
    this.#nodeDetailManager = new NodeDetailManager({
      network: params.network,
      keyType: 'secp256k1',
      sigType: 'ecdsa-secp256k1',
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
    const { nodeEndpoints, nodeIndexes } = await this.#getNodeDetails();
    const curve = getSecp256K1Curve();
    const sessionKeyPair = curve.genKeyPair();
    const sessionPubKey = sessionKeyPair.getPublic();
    const sessionPubKeyX = sessionPubKey.getX().toString('hex');
    const sessionPubKeyY = sessionPubKey.getY().toString('hex');

    // commit idToken to nodes
    const commitmentResults = await commitmentRequest({
      idToken: params.idTokens[0],
      verifier: params.verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: nodeEndpoints,
      indexes: nodeIndexes,
    });
    // get auth tokens from nodes
    const authTokens = await authenticateUser({
      idToken: params.idTokens[0],
      verifier: params.verifier,
      verifierID: params.verifierID,
      sessionPrivateKey: sessionKeyPair.getPrivate().toString('hex'),
      endpoints: nodeEndpoints,
      commitmentSignatures: commitmentResults,
    });

    const hasValidEncKey = thresholdSame(
      authTokens.map((tokenData) => ({
        token: tokenData.authToken,
        keyIndex: tokenData.keyIndex,
      })),
      nodeEndpoints.length / 2,
    );
    return Promise.resolve({
      nodeAuthTokens: authTokens.map((tokenData) => ({
        authToken: tokenData.authToken,
        nodeIndex: tokenData.nodeIndex,
        nodePubKey: tokenData.nodePubKey,
      })),
      hasValidEncKey: Boolean(hasValidEncKey),
    });
  }

  /**
   * This function creates the encryption key which is used to encrypt/decrypt the secret data.
   *
   * @param params - The parameters for creating the encryption key.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.password - New password of the user.
   *
   * @returns A promise that resolves with the encryption key.
   */
  async createEncKey(
    params: CreateEncryptionKeyParams,
  ): Promise<CreateEncryptionKeyResult> {
    const { nodeAuthTokens, password, verifier, verifierId } = params;
    const { nodeEndpoints, nodeIndexes, nodePubkeys } =
      await this.#getNodeDetails();
    const passwordBytes = new TextEncoder().encode(password);
    const hashedInput = keccak256(passwordBytes);
    const randomScalar = generateRandomScalar();
    const seed = OPRF.localEval(randomScalar, hashedInput);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    await storeKeyShares(nodeEndpoints, {
      nodeIndexes,
      nodePubkeys,
      verifier,
      verifierId,
      authTokens: nodeAuthTokens,
      keyIndex: 1,
      oprfKey: randomScalar,
      authPubKey: authKeyPair.pk,
    });
    const encKey = deriveEncryptionKey(seed);

    return {
      authKeyPair: {
        privKey: authKeyPair.sk,
        pubKey: authKeyPair.pk,
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
   * @returns A promise that resolves with the encryption key.
   */
  async recoverEncKey(
    params: RecoverEncryptionKeyParams,
  ): Promise<RecoverEncryptionKeyResult> {
    const { nodeAuthTokens, password, verifier, verifierId } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const seed = await recoverTOPRFSeed({
      authTokens: nodeAuthTokens,
      endpointsMap: nodeEndpointsMap,
      verifier,
      verifierId,
      password,
    });
    const authKeyPair = deriveAuthenticationKeyPair(seed);
    const encKeyPair = deriveEncryptionKey(seed);
    resetRateLimits({
      authTokens: nodeAuthTokens,
      endpointsMap: nodeEndpointsMap,
      verifier,
      verifierId,
    }).catch((error) => {
      console.error('Error resetting rate limits', error);
    });
    return {
      authKeyPair: {
        privKey: authKeyPair.sk,
        pubKey: authKeyPair.pk,
      },
      encKey: encKeyPair,
    };
  }

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
  async storeSecretData(params: StoreSecretDataParams): Promise<void> {
    const { nodeAuthTokens } = params;

    const metadataStore = await this.#getMetadataStore(nodeAuthTokens);
    await metadataStore.storeSecretData(
      params.secretData,
      params.encKey,
      params.authKeyPair,
    );
  }

  /**
   * This function decrypts the secret data using the decryption key and returns the decrypted secret data.
   *
   * @param params - The parameters for fetching the secret data.
   * @param params.nodeAuthTokens - The tokens issued by the nodes on authenticating the user.
   * @param params.decKey - The decryption key to be used to decrypt the secret data.
   * @param params.authKeyPair - The authentication key to be used to provide valid signature for fetching the secret data.
   *
   * @returns A promise that resolves with the decrypted secret data. Null if no secret data is found.
   */
  async fetchSecretData(
    params: FetchSecretDataParams,
  ): Promise<FetchSecretDataResult | null> {
    const metadataStore = await this.#getMetadataStore(params.nodeAuthTokens);
    return metadataStore.fetchSecretData(params.decKey, params.authKeyPair);
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
      nodeEndpointsMap: torusIndexes.reduce<Record<number, string>>(
        (acc, index) => {
          acc[index] = torusNodeSSSEndpoints[index - 1];
          return acc;
        },
        {},
      ),
      nodeIndexes: torusIndexes,
      nodePubkeys: torusNodePub,
    };
  }

  /**
   * Creates the metadata store instance.
   *
   * @param nodeAuthTokens - The node auth tokens from the authenticate function.
   *
   * @returns The metadata store.
   */
  async #getMetadataStore(
    nodeAuthTokens: NodeAuthTokens,
  ): Promise<MetadataStore> {
    const { nodeIndexes, nodeEndpoints } = await this.#getNodeDetails();
    const metadataEndpoints = await this.#getMetadataEndpoints(nodeEndpoints);
    const metadataStore = new MetadataStore({
      authTokens: nodeAuthTokens,
      nodeEndpoints: metadataEndpoints,
      nodeIndexes,
    });

    return metadataStore;
  }

  /**
   * Gets the metadata endpoints.
   *
   * @param nodeEndpoints - The node endpoints.
   *
   * @returns The metadata endpoints.
   */
  async #getMetadataEndpoints(nodeEndpoints: string[]): Promise<string[]> {
    return nodeEndpoints.map((endpoint) => {
      const url = new URL(endpoint);
      return `${url.origin}/metadata`;
    });
  }
}
