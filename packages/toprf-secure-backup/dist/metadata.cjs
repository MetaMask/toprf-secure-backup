"use strict";
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
var _MetadataStore_instances, _MetadataStore_feature, _MetadataStore_nodeEndpointsMap, _MetadataStore_addData, _MetadataStore_getAllDataItems, _MetadataStore_thresholdCheck, _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest, _MetadataStore_generatePayloadForGetSecretDataRequest, _MetadataStore_generatePayloadSignature, _MetadataStore_getAuthTokenToMetadataEndpointsMap, _MetadataStore_encryptData, _MetadataStore_decryptData;
Object.defineProperty(exports, "__esModule", { value: true });
exports.MetadataStore = exports.MetadataStoreError = void 0;
const auth_network_utils_1 = require("@metamask/auth-network-utils");
const aes_1 = require("@noble/ciphers/aes");
const webcrypto_1 = require("@noble/ciphers/webcrypto");
const secp256k1_1 = require("@noble/curves/secp256k1");
const sha3_1 = require("@noble/hashes/sha3");
const utils_1 = require("@noble/hashes/utils");
/**
 * Error class for metadata store.
 */
class MetadataStoreError extends Error {
    /**
     * Constructor for MetadataStoreError.
     *
     * @param message - The error message.
     */
    constructor(message) {
        super(message);
        this.name = 'MetadataStoreError';
        Object.setPrototypeOf(this, MetadataStoreError.prototype);
    }
}
exports.MetadataStoreError = MetadataStoreError;
/**
 * MetadataStore class.
 *
 * This class is used to store and retrieve encrypted account metadata for the
 * given feature.
 */
class MetadataStore {
    /**
     *
     * @param options - The initialization options for the metadata store.
     * @param options.nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
     * @param options.storageLocation - The storage location of the metadata.
     */
    constructor(options) {
        _MetadataStore_instances.add(this);
        _MetadataStore_feature.set(this, 'srp-backup');
        _MetadataStore_nodeEndpointsMap.set(this, void 0);
        __classPrivateFieldSet(this, _MetadataStore_nodeEndpointsMap, options.nodeEndpointsMap, "f");
    }
    /**
     * Encrypts the secret data and stores it in the metadata store.
     *
     * @param params - The parameters for storing the secret data.
     * @param params.secretData - The secret data to be stored.
     * @param params.encKey - The encryption key to be used for encrypting the secret data.
     * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
     * @param params.nodeAuthTokens - The array of auth tokens to be used for authenticating against the metadata server.
     * @returns A promise that resolves when the secret data is stored.
     */
    async addSecretDataItem(params) {
        try {
            const { secretData, encKey, nodeAuthTokens, authKeyPair } = params;
            const endPointToAuthTokenMap = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_getAuthTokenToMetadataEndpointsMap).call(this, nodeAuthTokens);
            const promises = Object.entries(endPointToAuthTokenMap).map(async ([endpoint, authToken]) => {
                return __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_addData).call(this, {
                    secretData,
                    encKey,
                    authKeyPair,
                    metadataEndpoint: endpoint,
                    authToken,
                });
            });
            const thresholdCount = Math.floor(Object.keys(endPointToAuthTokenMap).length / 2) + 1;
            await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_thresholdCheck).call(this, promises, thresholdCount);
        }
        catch (error) {
            if (error instanceof auth_network_utils_1.SomeError) {
                throw new MetadataStoreError(`failed to store metadata: ${error.predicate}`);
            }
            throw new MetadataStoreError(`failed to fetch metadata: ${error.message}`);
        }
    }
    /**
     * Fetches the secret data from the metadata store and decrypts it.
     *
     * @param encKey - The encryption key to be used for decrypting the secret data.
     * @param authKeyPair - The authentication key pair to be used for authenticating the secret data.
     * @returns A promise that resolves with the decrypted secret data.
     */
    async fetchAllSecretDataItems(encKey, authKeyPair) {
        try {
            const promises = Array.from(__classPrivateFieldGet(this, _MetadataStore_nodeEndpointsMap, "f").values()).map(async (metadataEndpoint) => {
                return __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_getAllDataItems).call(this, {
                    encKey,
                    authKeyPair,
                    metadataEndpoint,
                });
            });
            const thresholdCount = Math.floor(__classPrivateFieldGet(this, _MetadataStore_nodeEndpointsMap, "f").size / 2) + 1;
            const thresholdResult = await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_thresholdCheck).call(this, promises, thresholdCount);
            if (thresholdResult?.length === 0 || !thresholdResult) {
                return null;
            }
            return thresholdResult;
        }
        catch (error) {
            if (error instanceof auth_network_utils_1.SomeError) {
                throw new MetadataStoreError(`failed to fetch metadata: ${error.predicate}`);
            }
            throw new MetadataStoreError(`failed to fetch metadata: ${error.message}`);
        }
    }
}
exports.MetadataStore = MetadataStore;
_MetadataStore_feature = new WeakMap(), _MetadataStore_nodeEndpointsMap = new WeakMap(), _MetadataStore_instances = new WeakSet(), _MetadataStore_addData = 
/**
 * Encrypts the secret data and inserts or appends it in the metadata store.
 *
 * @param params - The parameters for storing the secret data.
 * @param params.secretData - The secret data to be stored.
 * @param params.encKey - The encryption key to be used for encrypting the secret data.
 * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
 * @param params.metadataEndpoint - The metadata server endpoint to be used for storing the secret data.
 * @param params.authToken - The auth token to be used for authentication for the metadata server.
 * @returns A promise that resolves when the secret data is stored.
 */
async function _MetadataStore_addData(params) {
    try {
        const url = `${params.metadataEndpoint}/enc_account_data/set`;
        const encryptedData = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_encryptData).call(this, params.secretData, params.encKey);
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest).call(this, encryptedData, params.authKeyPair, params.authToken);
        const requestBody = JSON.stringify(payload);
        const response = await fetch(url, {
            headers: {
                // eslint-disable-next-line @typescript-eslint/naming-convention
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: requestBody,
        });
        if (!response.ok) {
            const responseBody = await response.json();
            throw new Error(`HTTP error message: ${responseBody.error}`);
        }
        const jsonData = await response.json();
        return jsonData.success;
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to upsert metadata: ${errorMessage}`);
    }
}, _MetadataStore_getAllDataItems = 
/**
 * Fetches all the secret data from the metadata store by provided public key and decrypts it.
 *
 * @param params - The parameters for fetching the secret data.
 * @param params.encKey - The encryption key to be used for decrypting the secret data.
 * @param params.authKeyPair - The authentication key pair to be used for authenticating the secret data.
 * @param params.metadataEndpoint - The metadata server endpoint to be used for fetching the secret data.
 * @returns A promise that resolves with the decrypted secret data.
 */
async function _MetadataStore_getAllDataItems(params) {
    try {
        const url = `${params.metadataEndpoint}/enc_account_data/get`;
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForGetSecretDataRequest).call(this, params.authKeyPair);
        const response = await fetch(url, {
            headers: {
                // eslint-disable-next-line @typescript-eslint/naming-convention
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify(payload),
        });
        if (!response.ok) {
            const responseBody = await response.json();
            throw new Error(`HTTP error message: ${responseBody.error}`);
        }
        const jsonData = await response.json();
        if (!jsonData.data) {
            throw new MetadataStoreError('Failed to fetch metadata');
        }
        const secretData = jsonData.data.map((data) => {
            const rawData = new Uint8Array(Buffer.from(data, 'base64'));
            return __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_decryptData).call(this, rawData, params.encKey);
        });
        return secretData;
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to fetch metadata: ${errorMessage}`);
    }
}, _MetadataStore_thresholdCheck = 
/**
 * Validates Metadata Responses with threshold check.
 *
 * Criteria to be met:
 * Out of n results, t items must share the same value.
 *
 * @param promises - The array of promises to be validated.
 * @param thresholdCount - The threshold value to be used for the threshold check.
 * @returns The validated result which satisfies the threshold check.
 */
async function _MetadataStore_thresholdCheck(promises, thresholdCount) {
    const results = await (0, auth_network_utils_1.Some)(promises, async (resultArray) => {
        const tResult = (0, auth_network_utils_1.thresholdSame)(resultArray, thresholdCount);
        if (tResult) {
            return Promise.resolve(tResult);
        }
        return Promise.reject(new MetadataStoreError('Threshold not resolved'));
    });
    return results ?? null;
}, _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest = function _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest(rawData, authKeyPair, authToken) {
    const timestamp = Date.now().toString();
    const feature = __classPrivateFieldGet(this, _MetadataStore_feature, "f");
    const base64Data = Buffer.from(rawData).toString('base64');
    const { pk, sk } = authKeyPair;
    const signature = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadSignature).call(this, { data: base64Data, timestamp, feature, authToken }, sk);
    const pubKey = (0, utils_1.bytesToHex)(pk);
    return {
        data: base64Data,
        signature,
        feature,
        timestamp,
        authToken,
        pubKey,
    };
}, _MetadataStore_generatePayloadForGetSecretDataRequest = function _MetadataStore_generatePayloadForGetSecretDataRequest(authKeyPair) {
    const timestamp = Date.now().toString();
    const feature = __classPrivateFieldGet(this, _MetadataStore_feature, "f");
    const { pk, sk } = authKeyPair;
    const signature = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadSignature).call(this, { feature, timestamp }, sk);
    const pubKey = (0, utils_1.bytesToHex)(pk);
    return {
        feature,
        pubKey,
        timestamp,
        signature,
    };
}, _MetadataStore_generatePayloadSignature = function _MetadataStore_generatePayloadSignature(payload, privKey) {
    const payloadString = (0, auth_network_utils_1.safeStringify)(payload);
    const hash = (0, sha3_1.keccak_256)(payloadString);
    const signature = secp256k1_1.secp256k1.sign(hash, privKey);
    return signature.toCompactHex();
}, _MetadataStore_getAuthTokenToMetadataEndpointsMap = function _MetadataStore_getAuthTokenToMetadataEndpointsMap(nodeAuthTokens) {
    const endPointToAuthTokenMap = {};
    nodeAuthTokens.forEach(({ nodeIndex, authToken }) => {
        const endpoint = __classPrivateFieldGet(this, _MetadataStore_nodeEndpointsMap, "f").get(nodeIndex);
        if (!endpoint) {
            throw new MetadataStoreError(`Endpoint not found for node index: ${nodeIndex}`);
        }
        endPointToAuthTokenMap[endpoint] = authToken;
    });
    return endPointToAuthTokenMap;
}, _MetadataStore_encryptData = function _MetadataStore_encryptData(data, encryptionKey) {
    const aesGcm = (0, webcrypto_1.managedNonce)(aes_1.gcm)(encryptionKey);
    const ciphertext = aesGcm.encrypt(data);
    return ciphertext;
}, _MetadataStore_decryptData = function _MetadataStore_decryptData(cipherText, decryptionKey) {
    const aesGcm = (0, webcrypto_1.managedNonce)(aes_1.gcm)(decryptionKey);
    const decryptedData = aesGcm.decrypt(cipherText);
    return decryptedData;
};
//# sourceMappingURL=metadata.cjs.map