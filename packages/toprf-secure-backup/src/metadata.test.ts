import { randomBytes, utf8ToBytes } from '@noble/hashes/utils';

import { METADATA_NODES_ENDPOINTS_MAP } from './constants';
import type { KeyPair } from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataStore } from './metadata';

const MOCK_SEED = randomBytes(32);
const NODE_ENDPOINTS_MAP = METADATA_NODES_ENDPOINTS_MAP;
const secretData = utf8ToBytes('test-secret-data');

/**
 * Creates a mock MetadataStore instance.
 *
 * @param nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
 * @returns A mock MetadataStore instance.
 */
function createMockMetadataStore(
  nodeEndpointsMap: { [nodeIndex: string]: string } = NODE_ENDPOINTS_MAP,
): MetadataStore {
  return new MetadataStore({ nodeEndpointsMap });
}

describe('MetadataStore', () => {
  let encKey: Uint8Array;
  let authKeyPair: KeyPair;

  beforeAll(async () => {
    encKey = deriveEncryptionKey(MOCK_SEED);
    authKeyPair = deriveAuthenticationKeyPair(MOCK_SEED);
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = createMockMetadataStore();

    await metadataStore.addSecretDataItem({
      secretData,
      encKey,
      authKeyPair,
    });

    const result = await metadataStore.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
    );
    expect(result).not.toBeNull();
    expect(result?.[0]).toStrictEqual(secretData);
  });

  it('should be able to store/fetch data with different instances', async () => {
    const metadataStore1 = createMockMetadataStore();
    const metadataStore2 = createMockMetadataStore();

    await metadataStore1.addSecretDataItem({
      secretData,
      encKey,
      authKeyPair,
    });

    const result = await metadataStore2.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
    );
    expect(result).not.toBeNull();
    expect(result?.[0]).toStrictEqual(secretData);
  });

  it('should get null if metadata key not found', async () => {
    const metadataStore = createMockMetadataStore();

    const randomSeed = randomBytes(32);
    const randomAuthKeyPair = deriveAuthenticationKeyPair(randomSeed);
    const result = await metadataStore.fetchAllSecretDataItems(
      deriveEncryptionKey(randomSeed),
      randomAuthKeyPair,
    );
    expect(result).toBeNull();
  });

  it('should an error if the data is not present in the metadata response', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        return Promise.resolve({
          ok: true,
          status: 200,
          statusText: 'OK',
          /**
           * @returns json object
           */
          json: async () => Promise.resolve({ success: true }),
          // eslint-disable-next-line no-restricted-globals
        } as Response);
      });

    const metadataStore = createMockMetadataStore();

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });

  it('should throw an error if the threshold is not met', async () => {
    const metadataStore = createMockMetadataStore();

    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async (input) => {
        const url = new URL(input as string);
        const nodeIndex = url.pathname.split('/')[1];
        return Promise.resolve({
          ok: true,
          status: 200,
          statusText: 'OK',
          /**
           * @returns json object
           */
          json: async () =>
            Promise.resolve({
              data: [`SECRET_DATA_${nodeIndex}`],
              success: true,
            }),
          // eslint-disable-next-line no-restricted-globals
        } as Response);
      });

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalledTimes(5);
    jest.restoreAllMocks();
  });

  it('should handle network errors if the metadata server is down', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        return Promise.resolve({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          /**
           * @returns json object
           */
          json: async () => Promise.resolve({ error: 'Something went wrong!' }),
          // eslint-disable-next-line no-restricted-globals
        } as Response);
      });

    const metadataStore = createMockMetadataStore();

    await expect(
      metadataStore.addSecretDataItem({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Threshold not resolved');

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });

  it('should handle if it fails to read the http error response', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        throw new Error();
      });

    const metadataStore = createMockMetadataStore();

    await expect(
      metadataStore.addSecretDataItem({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Threshold not resolved');

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });
});
