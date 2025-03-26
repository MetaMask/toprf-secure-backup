import { FetchSecretDataParams, FetchSecretDataResult, KeyPair, StoreSecretDataParams } from "./interfaces";
import { deriveEncryptionKey } from "./keyDerivation";
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils";
import { gcm } from "@noble/ciphers/aes";
import { bytesToUtf8 } from "@noble/ciphers/utils";
import { sha256 } from "@noble/hashes/sha256";

export class MetadataStore {
  readonly #feature = 'srp_backup';

  // Nonce size for AES-256-GCM
  readonly #nonceSize = 24;
  
  readonly #metadataStoreUrl = 'http://localhost:5051/metadata';

  /**
   * Encrypts the secret data and stores it in the metadata store.
   * 
   * @param {StoreSecretDataParams} params - The parameters for storing the secret data.
   * @returns {Promise<void>} A promise that resolves when the secret data is stored.
   */
  async storeSecretData(params: StoreSecretDataParams): Promise<void> {
    await this.#upsertData(params);
  }

  /**
   * Fetches the secret data from the metadata store and decrypts it.
   * 
   * @param {FetchSecretDataParams} params - The parameters for fetching the secret data.
   * @returns {Promise<FetchSecretDataResult>} A promise that resolves with the decrypted secret data.
   */
  async fetchSecretData(params: FetchSecretDataParams): Promise<FetchSecretDataResult> {
    const data = await this.#getDataByKey(params);
    return data;
  }

  /**
   * Encrypts the secret data and inserts or updates it in the metadata store.
   * 
   * @param {StoreSecretDataParams} params - The parameters for storing the secret data.
   * @returns {Promise<void>} A promise that resolves when the secret data is stored.
   */
  async #upsertData(params: StoreSecretDataParams): Promise<void> {
    const data = this.#encryptData(params.secretData, params.keyPair.privKey);
    const key = this.#getMetadataKey(params.keyPair);

    const response = await fetch(`${this.#metadataStoreUrl}/${key}`, {
      headers: {
        'Content-Type': 'application/json',
      },
      method: 'PUT',
      body: JSON.stringify({
        data,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to upsert metadata');
    }
  }

  /**
   * Fetches the secret data from the metadata store by provided public key and decrypts it.
   * 
   * @param {FetchSecretDataParams} params - The parameters for fetching the secret data.
   * @returns {Promise<FetchSecretDataResult>} A promise that resolves with the decrypted secret data.
   */
  async #getDataByKey({ keyPair }: FetchSecretDataParams): Promise<FetchSecretDataResult> {
    const key = this.#getMetadataKey(keyPair);
    
    const response = await fetch(`${this.#metadataStoreUrl}/${key}`, {
      headers: {
        'Content-Type': 'application/json',
      },
      method: 'GET',
    });

    if (!response.ok) {
      throw new Error('Failed to fetch metadata');
    }

    const encryptedData = await response.json();
    const secretData = this.#decryptData(encryptedData, keyPair.privKey);
    return {
      secretData,
    }
  }

  #getMetadataKey(keyPair: KeyPair): string {
    const pubKey = keyPair.pubKey;
    const pubKeyHex = Buffer.from(pubKey).toString('hex');
    const rawHashedKey = sha256(this.#feature + pubKeyHex);

    return bytesToHex(rawHashedKey);
  }

  /**
   * Derive AES-256 key from seed and encrypt the data using the key.
   * 
   * We might not need it if we're using Profile-Sync SDK since encryption is handled in the SDK
   * 
   * @param {string} data - The secret data to be encrypted.
   * @param {Uint8Array} seed - The seed to derive the encryption key from.
   * @returns {string} The encrypted data.
   */
  #encryptData(data: string, seed: Uint8Array): string {
    const encryptionKey = deriveEncryptionKey(seed);
    const nonce = randomBytes(this.#nonceSize);
    const rawData = utf8ToBytes(data);

    const aes = gcm(encryptionKey, nonce);
    const ciphertext = aes.encrypt(rawData);

    const cipherTextCombinedWithNonce = concatBytes(nonce, ciphertext);

    return Buffer.from(cipherTextCombinedWithNonce).toString('base64');
  }

  /**
   * Decrypt the data using the encryption key.
   * 
   * @param {string} encryptedData - The encrypted data to be decrypted.
   * @param {Uint8Array} seed - The seed to derive the encryption key from.
   * @returns {string} The decrypted data.
   */
  #decryptData(cipherTextCombinedWithNonceString: string, seed: Uint8Array): string {
    const encryptionKey = deriveEncryptionKey(seed);
    const cipherTextCombinedWithNonce = new Uint8Array(
      Buffer.from(cipherTextCombinedWithNonceString, 'base64')
    );
    const nonce = cipherTextCombinedWithNonce.slice(0, this.#nonceSize);

    const rawEncData = cipherTextCombinedWithNonce.slice(this.#nonceSize);

    const aes = gcm(encryptionKey, nonce);
    const rawData = aes.decrypt(rawEncData);

    return bytesToUtf8(rawData);
  }
}
