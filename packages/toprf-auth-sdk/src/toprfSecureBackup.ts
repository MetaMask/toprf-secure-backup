import { getSecp256K1Curve, thresholdSame } from '@metamask/auth-network-utils';
import type {
  INodePub,
  TORUS_SAPPHIRE_NETWORK_TYPE,
} from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { authenticateUser } from './authenticateRequest';
import { commitmentRequest } from './commitmentRequest';
import type {
  AuthenticateParams,
  AuthenticateResult,
  IToprfSecureBackup,
} from './interfaces';

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
   * Authenticates the user and returns the authentication result
   * containing the auth tokens and the flag indicating if user has valid encryption key.
   *
   * @param params - The authenticate parameters.
   * @returns The authenticate result.
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
   * Gets the node details.
   *
   * @returns The node details containing the node endpoints, indexes and pubkeys.
   */
  async #getNodeDetails(): Promise<{
    nodeEndpoints: string[];
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
      nodeIndexes: torusIndexes,
      nodePubkeys: torusNodePub,
    };
  }
}
