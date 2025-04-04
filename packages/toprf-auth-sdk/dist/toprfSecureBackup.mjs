var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _ToprfSecureBackup_instances, _ToprfSecureBackup_nodeDetailManager, _ToprfSecureBackup_getNodeDetails;
import { getSecp256K1Curve, thresholdSame } from "@metamask/auth-network-utils";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { keccak256 } from "ethereum-cryptography/keccak";
import { authenticateUser } from "./authenticateRequest.mjs";
import { commitmentRequest } from "./commitmentRequest.mjs";
import { deriveAuthenticationKeyPair, deriveEncryptionKey } from "./keyDerivation.mjs";
import { OPRF, generateRandomScalar } from "./oprf.mjs";
import { resetRateLimits } from "./resetRateLimits.mjs";
import { storeKeyShares } from "./storeSharesRequest.mjs";
import { recoverTOPRFSeed } from "./toprfEvalRequest.mjs";
/**
 *
 */
export class ToprfSecureBackup {
    /**
     *
     * @param params - The parameters for the constructor.
     * @param params.network - The web3auth network to be used key management and authentication.
     */
    constructor(params) {
        _ToprfSecureBackup_instances.add(this);
        _ToprfSecureBackup_nodeDetailManager.set(this, void 0);
        __classPrivateFieldSet(this, _ToprfSecureBackup_nodeDetailManager, new NodeDetailManager({
            network: params.network,
            keyType: 'secp256k1',
            sigType: 'ecdsa-secp256k1',
        }), "f");
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
    async authenticate(params) {
        const { nodeEndpoints, nodeIndexes } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
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
        const hasValidEncKey = thresholdSame(authTokens.map((tokenData) => ({
            token: tokenData.authToken,
            keyIndex: tokenData.keyIndex,
        })), nodeEndpoints.length / 2);
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
    async createEncKey(params) {
        const { nodeAuthTokens, password, verifier, verifierId } = params;
        const { nodeEndpoints, nodeIndexes, nodePubkeys } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
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
        const encKeyPair = deriveEncryptionKey(seed);
        return {
            authKeyPair: {
                privKey: authKeyPair.sk,
                pubKey: authKeyPair.pk,
            },
            encKey: encKeyPair,
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
    async recoverEncKey(params) {
        const { nodeAuthTokens, password, verifier, verifierId } = params;
        const { nodeEndpointsMap } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
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
}
_ToprfSecureBackup_nodeDetailManager = new WeakMap(), _ToprfSecureBackup_instances = new WeakSet(), _ToprfSecureBackup_getNodeDetails = 
/**
 * Gets the node details.
 *
 * @returns The node details containing the node endpoints, indexes and pubkeys.
 */
async function _ToprfSecureBackup_getNodeDetails() {
    const { torusNodeSSSEndpoints, torusIndexes, torusNodePub } = await __classPrivateFieldGet(this, _ToprfSecureBackup_nodeDetailManager, "f").getNodeDetails({
        verifier: 'DEFAULT_VERIFIER',
        verifierId: 'DEFAULT_VERIFIER_ID',
    });
    if (!torusNodeSSSEndpoints || !torusIndexes || !torusNodePub) {
        throw new Error('Failed to get node details');
    }
    return {
        nodeEndpoints: torusNodeSSSEndpoints,
        nodeEndpointsMap: torusIndexes.reduce((acc, index) => {
            acc[index] = torusNodeSSSEndpoints[index - 1];
            return acc;
        }, {}),
        nodeIndexes: torusIndexes,
        nodePubkeys: torusNodePub,
    };
};
//# sourceMappingURL=toprfSecureBackup.mjs.map