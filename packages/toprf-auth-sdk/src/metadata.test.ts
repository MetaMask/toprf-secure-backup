import { randomBytes } from '@noble/hashes/utils';

import { MetadataStorageLocation, MetadataStore } from './metadata';

const MOCK_KEY_PAIR = {
  pubKey: randomBytes(32),
  privKey: randomBytes(32),
};

describe('MetadatStore', () => {
  it('should be able to initialize with default storage locations', () => {
    const metadataStore = new MetadataStore();
    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe('metadata-server');
  });

  it('should be able to initialize with profile-sync storage location', () => {
    const metadataStore = new MetadataStore({
      storageLocation: MetadataStorageLocation.PROFILE_SYNC,
    });
    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe('profile-sync');
  });

  it('should throw an error if invalid metadata server url is provided', async () => {
    const metadataStore = new MetadataStore({
      metadataServerUrl: 'https://invalid-url',
    });

    await expect(
      metadataStore.storeSecretData({
        secretData: 'SECRET_DATA',
        keyPair: MOCK_KEY_PAIR,
        nodeAuthTokens: [],
      }),
    ).rejects.toThrow('Metadata store is not using metadata server');

    await expect(
      metadataStore.fetchSecretData({
        keyPair: MOCK_KEY_PAIR,
      }),
    ).rejects.toThrow('Metadata store is not using metadata server');
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = new MetadataStore();
    const secretData = 'SECRET_DATA';

    await metadataStore.storeSecretData({
      secretData,
      keyPair: MOCK_KEY_PAIR,
      nodeAuthTokens: [],
    });

    const result = await metadataStore.fetchSecretData({
      keyPair: MOCK_KEY_PAIR,
    });
    expect(result).not.toBeNull();
    expect(result?.secretData).toBe(secretData);
  });

  it('should be able to store/fetch data with different instances', async () => {
    const metadataStore1 = new MetadataStore();
    const metadataStore2 = new MetadataStore();

    const secretData = 'SECRET_DATA';

    await metadataStore1.storeSecretData({
      secretData,
      keyPair: MOCK_KEY_PAIR,
      nodeAuthTokens: [],
    });

    const result = await metadataStore2.fetchSecretData({
      keyPair: MOCK_KEY_PAIR,
    });

    expect(result).not.toBeNull();
    expect(result?.secretData).toBe(secretData);
  });

  it('should get null if metadata key not found', async () => {
    const metadataStore = new MetadataStore();

    const result = await metadataStore.fetchSecretData({
      keyPair: {
        pubKey: randomBytes(32),
        privKey: randomBytes(32),
      },
    });

    expect(result).toBeNull();
  });

  it('should handle network errors', async () => {
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

    const metadataStore = new MetadataStore();

    await expect(
      metadataStore.storeSecretData({
        secretData: 'SECRET_DATA',
        keyPair: MOCK_KEY_PAIR,
        nodeAuthTokens: [],
      }),
    ).rejects.toThrow('Something went wrong!');

    expect(fetchSpy).toHaveBeenCalled();

    await expect(
      metadataStore.fetchSecretData({
        keyPair: MOCK_KEY_PAIR,
      }),
    ).rejects.toThrow('Something went wrong!');

    jest.restoreAllMocks();
  });

  it('should not make network requests to metadata server if profile-sync storage location is used', async () => {
    const metadataStore = new MetadataStore({
      storageLocation: MetadataStorageLocation.PROFILE_SYNC,
    });

    await expect(
      metadataStore.storeSecretData({
        secretData: 'SECRET_DATA',
        keyPair: MOCK_KEY_PAIR,
        nodeAuthTokens: [],
      }),
    ).rejects.toThrow('Metadata store is not using metadata server');

    await expect(
      metadataStore.fetchSecretData({
        keyPair: MOCK_KEY_PAIR,
      }),
    ).rejects.toThrow('Metadata store is not using metadata server');
  });
});
