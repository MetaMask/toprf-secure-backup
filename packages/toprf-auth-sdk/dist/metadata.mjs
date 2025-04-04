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
var _MetadataStore_instances, _MetadataStore_feature, _MetadataStore_storageLocation, _MetadataStore_nonceSize, _MetadataStore_metadataServerUrl, _MetadataStore_authToken, _MetadataStore_setData, _MetadataStore_batchSetData, _MetadataStore_getData, _MetadataStore_acquireLock, _MetadataStore_releaseLock, _MetadataStore_computeMetadataServerUrl, _MetadataStore_assertIsUsingMetadataServer, _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest, _MetadataStore_generatePayloadForGetSecretDataRequest, _MetadataStore_generatePayloadForLockRequests, _MetadataStore_generatePayloadSignature, _MetadataStore_encryptData, _MetadataStore_decryptData;
import { safeStringify } from "@metamask/auth-network-utils";
import { gcm } from "@noble/ciphers/aes";
import { bytesToUtf8 } from "@noble/ciphers/utils";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 as keccak256 } from "@noble/hashes/sha3";
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { DEFAULT_METADATA_SERVER_URL } from "./constants.mjs";
import { deriveAuthenticationKeyPair, deriveEncryptionKey } from "./keyDerivation.mjs";
export var MetadataStorageLocation;
(function (MetadataStorageLocation) {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    MetadataStorageLocation["METADATA_SERVER"] = "metadata-server";
    // eslint-disable-next-line @typescript-eslint/naming-convention
    MetadataStorageLocation["PROFILE_SYNC"] = "profile-sync";
})(MetadataStorageLocation || (MetadataStorageLocation = {}));
export var MetadataLockStatus;
(function (MetadataLockStatus) {
    MetadataLockStatus[MetadataLockStatus["FAILED"] = 0] = "FAILED";
    MetadataLockStatus[MetadataLockStatus["SUCCESS"] = 1] = "SUCCESS";
})(MetadataLockStatus || (MetadataLockStatus = {}));
/**
 * Error class for metadata store.
 */
export class MetadataStoreError extends Error {
    /**
     * Constructor for MetadataStoreError.
     *
     * @param message - The error message.
     */
    constructor(message) {
        super(message);
        this.name = 'MetadataStoreError';
    }
}
/**
 * MetadataStore class.
 *
 * This class is used to store and retrieve encrypted account metadata for the
 * given feature.
 */
export class MetadataStore {
    /**
     *
     * @param options - The initialization options for the metadata store.
     * @param options.authToken - The auth token to be used for authenticating requests to the metadata server.
     * @param options.storageLocation - The storage location of the metadata.
     * @param options.metadataServerUrl - The metadata server URL.
     */
    constructor({ authToken, storageLocation = MetadataStorageLocation.METADATA_SERVER, metadataServerUrl = DEFAULT_METADATA_SERVER_URL, }) {
        _MetadataStore_instances.add(this);
        _MetadataStore_feature.set(this, 'srp-backup');
        _MetadataStore_storageLocation.set(this, void 0);
        // Nonce size for AES-256-GCM
        _MetadataStore_nonceSize.set(this, 24);
        _MetadataStore_metadataServerUrl.set(this, '');
        _MetadataStore_authToken.set(this, void 0);
        __classPrivateFieldSet(this, _MetadataStore_storageLocation, storageLocation, "f");
        __classPrivateFieldSet(this, _MetadataStore_authToken, authToken, "f");
        if (storageLocation === MetadataStorageLocation.METADATA_SERVER) {
            __classPrivateFieldSet(this, _MetadataStore_metadataServerUrl, metadataServerUrl, "f");
        }
        else {
            // Otherwise, the Profile-Sync SDK will handle the storage url
        }
    }
    /**
     * Get the storage location of the metadata.
     *
     * @returns The storage location of the metadata.
     */
    get metadataStorageLocation() {
        return __classPrivateFieldGet(this, _MetadataStore_storageLocation, "f");
    }
    /**
     * Encrypts the secret data and stores it in the metadata store.
     *
     * @param secretData - The secret data to be stored.
     * @param seed - The seed to derive the encryption/authentication key from.
     * @returns A promise that resolves when the secret data is stored.
     */
    async storeSecretData(secretData, seed) {
        await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_setData).call(this, secretData, seed);
    }
    /**
     * Encrypts the secret data and stores it in the metadata store.
     *
     * @param secretData - The array of secret data to be stored.
     * @param seed - The seed to derive the encryption/authentication key from.
     * @returns A promise that resolves when the secret data is stored.
     */
    async storeSecretDataBatch(secretData, seed) {
        await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_batchSetData).call(this, secretData, seed);
    }
    /**
     * Fetches the secret data from the metadata store and decrypts it.
     *
     * @param seed - The seed to derive the encryption/authentication key from.
     * @returns A promise that resolves with the decrypted secret data.
     */
    async fetchSecretData(seed) {
        return await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_getData).call(this, seed);
    }
    /**
     * Acquires a lock on the metadata store.
     *
     * @param seed - The seed to derive the user public key.
     * @returns A promise that resolves with the lock id.
     */
    async acquireMetadataLock(seed) {
        const { status, id: lockId } = await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_acquireLock).call(this, seed);
        if (status !== MetadataLockStatus.SUCCESS) {
            throw new MetadataStoreError('Failed to acquire metadata lock');
        }
        if (!lockId) {
            throw new MetadataStoreError('Failed to acquire metadata lock. Missing lock id');
        }
        return lockId;
    }
    /**
     * Releases the lock on the metadata store.
     *
     * @param seed - The seed to derive the user public key.
     * @param lockId - The lock id to be released.
     * @returns A promise that resolves with the lock status.
     */
    async releaseMetadataLock(seed, lockId) {
        return await __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_releaseLock).call(this, seed, lockId);
    }
}
_MetadataStore_feature = new WeakMap(), _MetadataStore_storageLocation = new WeakMap(), _MetadataStore_nonceSize = new WeakMap(), _MetadataStore_metadataServerUrl = new WeakMap(), _MetadataStore_authToken = new WeakMap(), _MetadataStore_instances = new WeakSet(), _MetadataStore_setData = 
/**
 * Encrypts the secret data and inserts or updates it in the metadata store.
 *
 * @param secretData - The secret data to be stored.
 * @param seed - The seed to derive the encryption/authentication key from.
 * @returns A promise that resolves when the secret data is stored.
 */
async function _MetadataStore_setData(secretData, seed) {
    try {
        const url = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_computeMetadataServerUrl).call(this, 'set');
        const encryptedData = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_encryptData).call(this, secretData, seed);
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest).call(this, encryptedData, seed);
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
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to upsert metadata: ${errorMessage}`);
    }
}, _MetadataStore_batchSetData = 
/**
 * Encrypts the array of secret data and inserts them in the metadata store.
 *
 * @param secretData - The array of secret data to be stored.
 * @param seed - The seed to derive the encryption/authentication key from.
 * @returns A promise that resolves when the secret data is stored.
 */
async function _MetadataStore_batchSetData(secretData, seed) {
    try {
        const url = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_computeMetadataServerUrl).call(this, 'batch_set');
        const encryptedDataArray = secretData.map((secret) => ({
            data: __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_encryptData).call(this, secret, seed),
        }));
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest).call(this, encryptedDataArray, seed);
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
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to upsert metadata: ${errorMessage}`);
    }
}, _MetadataStore_getData = 
/**
 * Fetches the secret data from the metadata store by provided public key and decrypts it.
 *
 * @param seed - The seed to derive the encryption/authentication key from.
 * @returns A promise that resolves with the decrypted secret data.
 */
async function _MetadataStore_getData(seed) {
    try {
        const url = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_computeMetadataServerUrl).call(this, 'get');
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForGetSecretDataRequest).call(this, seed);
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
            return null;
        }
        const encryptionKey = deriveEncryptionKey(seed);
        const secretData = jsonData.data.map((data) => __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_decryptData).call(this, data, encryptionKey));
        return {
            secretData,
        };
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to fetch metadata: ${errorMessage}`);
    }
}, _MetadataStore_acquireLock = 
/**
 * Acquires a lock on the metadata store.
 *
 * @param seed - The seed to derive the user public key.
 * @returns A promise that resolves when the lock is acquired.
 */
async function _MetadataStore_acquireLock(seed) {
    try {
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForLockRequests).call(this, seed);
        const url = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_computeMetadataServerUrl).call(this, 'acquireLock');
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
        return {
            status: jsonData.status,
            id: jsonData.id,
        };
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to acquire metadata lock: ${errorMessage}`);
    }
}, _MetadataStore_releaseLock = 
/**
 * Releases the lock on the metadata store.
 *
 * @param seed - The seed to derive the user public key.
 * @param lockId - The lock id to be released.
 * @returns A promise that resolves with the lock status.
 */
async function _MetadataStore_releaseLock(seed, lockId) {
    try {
        const payload = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadForLockRequests).call(this, seed, lockId);
        const url = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_computeMetadataServerUrl).call(this, 'releaseLock');
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
        return jsonData.status;
    }
    catch (error) {
        const errorMessage = error.message || 'Unknown error';
        throw new MetadataStoreError(`failed to release metadata lock: ${errorMessage}`);
    }
}, _MetadataStore_computeMetadataServerUrl = function _MetadataStore_computeMetadataServerUrl(operation) {
    __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_assertIsUsingMetadataServer).call(this);
    let baseUrl = __classPrivateFieldGet(this, _MetadataStore_metadataServerUrl, "f");
    if (operation !== 'acquireLock' && operation !== 'releaseLock') {
        baseUrl = `${baseUrl}/enc_account_data`;
    }
    return `${baseUrl}/${operation}`;
}, _MetadataStore_assertIsUsingMetadataServer = function _MetadataStore_assertIsUsingMetadataServer() {
    if (__classPrivateFieldGet(this, _MetadataStore_storageLocation, "f") !== MetadataStorageLocation.METADATA_SERVER) {
        // TODO: use error constants
        throw new Error('Metadata store is not using metadata server');
    }
}, _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest = function _MetadataStore_generatePayloadForSetOrBatchSetSecretDataRequest(data, seed) {
    const timestamp = Date.now().toString();
    const feature = __classPrivateFieldGet(this, _MetadataStore_feature, "f");
    const authToken = __classPrivateFieldGet(this, _MetadataStore_authToken, "f");
    const { pk: pubKeyRaw, sk: privKey } = deriveAuthenticationKeyPair(seed);
    const pubKey = bytesToHex(pubKeyRaw);
    const signature = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadSignature).call(this, { data, timestamp, feature, authToken }, privKey);
    return {
        data,
        signature,
        feature,
        timestamp,
        authToken,
        pubKey,
    };
}, _MetadataStore_generatePayloadForGetSecretDataRequest = function _MetadataStore_generatePayloadForGetSecretDataRequest(seed) {
    const timestamp = Date.now().toString();
    const feature = __classPrivateFieldGet(this, _MetadataStore_feature, "f");
    const authToken = __classPrivateFieldGet(this, _MetadataStore_authToken, "f");
    const { pk: pubKeyRaw, sk: privKey } = deriveAuthenticationKeyPair(seed);
    const signature = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadSignature).call(this, { feature, timestamp, authToken }, privKey);
    const pubKey = bytesToHex(pubKeyRaw);
    return {
        feature,
        pubKey,
        timestamp,
        authToken,
        signature,
    };
}, _MetadataStore_generatePayloadForLockRequests = function _MetadataStore_generatePayloadForLockRequests(seed, lockId) {
    const { pk: pubKeyRaw, sk: privKey } = deriveAuthenticationKeyPair(seed);
    const data = { timestamp: Date.now() };
    // metadata server expects der encoded signature for lock requests
    const shouldDerEncoded = true;
    const signature = __classPrivateFieldGet(this, _MetadataStore_instances, "m", _MetadataStore_generatePayloadSignature).call(this, data, privKey, shouldDerEncoded);
    const key = bytesToHex(pubKeyRaw);
    const payloadForLockRequest = {
        data,
        signature,
        key,
    };
    if (lockId) {
        payloadForLockRequest.id = lockId;
    }
    return payloadForLockRequest;
}, _MetadataStore_generatePayloadSignature = function _MetadataStore_generatePayloadSignature(payload, privKey, shouldDerEncoded = false) {
    const payloadString = safeStringify(payload);
    const hash = keccak256(payloadString);
    const signature = secp256k1.sign(hash, privKey);
    if (shouldDerEncoded) {
        return signature.toDERHex();
    }
    return signature.toCompactHex();
}, _MetadataStore_encryptData = function _MetadataStore_encryptData(data, seed) {
    const encryptionKey = deriveEncryptionKey(seed);
    const nonce = randomBytes(__classPrivateFieldGet(this, _MetadataStore_nonceSize, "f"));
    const rawData = utf8ToBytes(data);
    const aes = gcm(encryptionKey, nonce);
    const ciphertext = aes.encrypt(rawData);
    const cipherTextCombinedWithNonce = concatBytes(nonce, ciphertext);
    return Buffer.from(cipherTextCombinedWithNonce).toString('base64');
}, _MetadataStore_decryptData = function _MetadataStore_decryptData(cipherTextCombinedWithNonceString, encryptionKey) {
    const cipherTextCombinedWithNonce = new Uint8Array(Buffer.from(cipherTextCombinedWithNonceString, 'base64'));
    const nonce = cipherTextCombinedWithNonce.slice(0, __classPrivateFieldGet(this, _MetadataStore_nonceSize, "f"));
    const rawEncData = cipherTextCombinedWithNonce.slice(__classPrivateFieldGet(this, _MetadataStore_nonceSize, "f"));
    const aes = gcm(encryptionKey, nonce);
    const rawData = aes.decrypt(rawEncData);
    return bytesToUtf8(rawData);
};
//# sourceMappingURL=metadata.mjs.map