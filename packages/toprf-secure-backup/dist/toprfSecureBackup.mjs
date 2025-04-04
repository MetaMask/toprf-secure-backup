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
var _ToprfSecureBackup_instances, _ToprfSecureBackup_nodeDetailManager, _ToprfSecureBackup_metadataStoreCache, _ToprfSecureBackup_getNodeDetails, _ToprfSecureBackup_createMetadataStore, _ToprfSecureBackup_getMetadataEndpointsMap;
import { getSecp256K1Curve, thresholdSame } from "@metamask/auth-network-utils";
import { sha256 } from "@noble/hashes/sha256";
import { toBytes } from "@noble/hashes/utils";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { authenticateUser } from "./authenticateRequest.mjs";
import { commitIdToken } from "./commitRequest.mjs";
import { EXISTING_USER_AUTHENTICATION_THRESHOLD } from "./constants.mjs";
import { deriveAuthenticationKeyPair, deriveEncryptionKey } from "./keyDerivation.mjs";
import { MetadataStore } from "./metadata.mjs";
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
        _ToprfSecureBackup_metadataStoreCache.set(this, void 0);
        __classPrivateFieldSet(this, _ToprfSecureBackup_nodeDetailManager, new NodeDetailManager({
            network: params.network,
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
        const { nodeEndpoints } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
        const curve = getSecp256K1Curve();
        const sessionKeyPair = curve.genKeyPair();
        const sessionPrivKeyBuffer = sessionKeyPair.getPrivate().toBuffer();
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
            sessionPrivateKey: sessionPrivKeyBuffer,
            endpoints: nodeEndpoints,
            commitmentSignatures: commitmentResults,
        });
        const hasValidEncKey = thresholdSame(authTokens.map((tokenData) => ({
            token: tokenData.authToken,
            keyIndex: tokenData.keyIndex,
        })), EXISTING_USER_AUTHENTICATION_THRESHOLD);
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
     * This function creates the oprf encryption key seed and authentication key pair.
     *
     * @param params - The parameters for creating the encryption key.
     * @param params.password - New password of the user.
     *
     * @returns A promise that resolves with the encryption key.
     */
    createLocalEncKey(params) {
        const { password } = params;
        const passwordBytes = toBytes(password);
        const hashedInput = sha256(passwordBytes);
        const oprfKey = generateRandomScalar();
        const seed = OPRF.localEval(oprfKey, hashedInput);
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
        const { nodeEndpointsMap } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
        const { oprfKey, authKeyPair, encKey } = this.createLocalEncKey({
            password,
        });
        await storeKeyShares({
            nodeEndpointsMap,
            verifier,
            verifierId,
            authTokens: nodeAuthTokens,
            keyIndex: 1,
            oprfKey,
            authPubKey: authKeyPair.pk,
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
     * @returns A promise that resolves with the encryption key.
     */
    async recoverEncKey(params) {
        const { nodeAuthTokens, password, verifier, verifierId } = params;
        const { nodeEndpointsMap } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
        const passwordBytes = toBytes(password);
        const userPasswordHash = sha256(passwordBytes);
        const seed = await recoverTOPRFSeed({
            authTokens: nodeAuthTokens,
            nodeEndpointsMap,
            verifier,
            verifierId,
            userPasswordHash,
        });
        const authKeyPair = deriveAuthenticationKeyPair(seed);
        const encKeyPair = deriveEncryptionKey(seed);
        resetRateLimits({
            authTokens: nodeAuthTokens,
            nodeEndpointsMap,
            verifier,
            verifierId,
        }).catch((error) => {
            console.error('Error resetting rate limits', error);
        });
        return {
            authKeyPair: {
                sk: authKeyPair.sk,
                pk: authKeyPair.pk,
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
    async addSecretDataItem(params) {
        const metadataStore = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_createMetadataStore).call(this);
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
     * @returns A promise that resolves with the decrypted secret data. Null if no secret data is found.
     */
    async fetchAllSecretDataItems(params) {
        const metadataStore = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_createMetadataStore).call(this);
        return metadataStore.fetchAllSecretDataItems(params.decKey, params.authKeyPair);
    }
}
_ToprfSecureBackup_nodeDetailManager = new WeakMap(), _ToprfSecureBackup_metadataStoreCache = new WeakMap(), _ToprfSecureBackup_instances = new WeakSet(), _ToprfSecureBackup_getNodeDetails = 
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
}, _ToprfSecureBackup_createMetadataStore = 
/**
 * Creates and caches the metadata store instance.
 *
 * @returns The metadata store.
 */
async function _ToprfSecureBackup_createMetadataStore() {
    if (__classPrivateFieldGet(this, _ToprfSecureBackup_metadataStoreCache, "f")) {
        return __classPrivateFieldGet(this, _ToprfSecureBackup_metadataStoreCache, "f");
    }
    const { nodeEndpointsMap } = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getNodeDetails).call(this);
    const metadataEndpointsMap = await __classPrivateFieldGet(this, _ToprfSecureBackup_instances, "m", _ToprfSecureBackup_getMetadataEndpointsMap).call(this, nodeEndpointsMap);
    const metadataStore = new MetadataStore({
        nodeEndpointsMap: metadataEndpointsMap,
    });
    __classPrivateFieldSet(this, _ToprfSecureBackup_metadataStoreCache, metadataStore, "f");
    return metadataStore;
}, _ToprfSecureBackup_getMetadataEndpointsMap = 
/**
 * Gets the metadata endpoints.
 *
 * @param nodeEndpointsMap - The node endpoints map.
 *
 * @returns The metadata endpoints map with node index as key and metadata endpoint as value.
 */
async function _ToprfSecureBackup_getMetadataEndpointsMap(nodeEndpointsMap) {
    const metadataEndpointsMap = new Map();
    Object.entries(nodeEndpointsMap).forEach(([key, value]) => {
        const url = new URL(value);
        metadataEndpointsMap.set(Number(key), `${url.origin}/metadata`);
    });
    return metadataEndpointsMap;
};
//# sourceMappingURL=toprfSecureBackup.mjs.map