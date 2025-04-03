import { getSecp256K1Curve, thresholdSame } from '@metamask/auth-network-utils';
import { sha256 } from '@noble/hashes/sha256';
import { toBytes } from '@noble/hashes/utils';
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
  IToprfSecureBackup,
  CreateEncryptionKeyParams,
  CreateEncryptionKeyResult,
} from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { OPRF, generateRandomScalar } from './oprf';
import { storeKeyShares } from './storeSharesRequest';

/**
 *
 */
export class ToprfSecretBackup implements Partial<IToprfSecureBackup> {
  readonly #nodeDetailManager: NodeDetailManager;

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
    const { nodeEndpoints } = await this.#getNodeDetails();
    const curve = getSecp256K1Curve();
    const sessionKeyPair = curve.genKeyPair();
    const sessionPubKey = sessionKeyPair.getPublic();
    const sessionPubKeyX = sessionPubKey.getX().toString('hex');
    const sessionPubKeyY = sessionPubKey.getY().toString('hex');

    // commit idToken to nodes
    const commitmentResults = await commitIdToken({
      idToken: params.idTokens[0],
      verifier: params.verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints: nodeEndpoints,
    });
    // get auth tokens from nodes
    const authTokens = await authenticateUser({
      idToken: params.idTokens[0],
      verifier: params.verifier,
      verifierID: params.verifierID,
      sessionPrivateKey: sessionKeyPair.getPrivate(),
      endpoints: nodeEndpoints,
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
   * @returns A promise that resolves with the encryption key.
   */
  async createEncKey(
    params: CreateEncryptionKeyParams,
  ): Promise<CreateEncryptionKeyResult> {
    const { nodeAuthTokens, password, verifier, verifierId } = params;
    const { nodeEndpointsMap } = await this.#getNodeDetails();
    const passwordBytes = toBytes(password);
    const hashedInput = sha256(passwordBytes);
    const oprfKey = generateRandomScalar();
    const seed = OPRF.localEval(oprfKey, hashedInput);
    const authKeyPair = deriveAuthenticationKeyPair(seed);

    await storeKeyShares({
      nodeEndpointsMap,
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
}
