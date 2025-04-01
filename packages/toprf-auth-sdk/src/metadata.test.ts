import { randomBytes } from '@noble/hashes/utils';

import {
  MetadataLockStatus,
  MetadataStorageLocation,
  MetadataStore,
  MetadataStoreError,
} from './metadata';
import { generateMockAuthTokenForMetadataRequests } from '../tests/metadata-utils';

const MOCK_SEED = randomBytes(32);
const METADATA_SERVER_URL = 'http://localhost:5051';

describe('MetadataStore', () => {
  let authToken: string;
  const verifier = 'torus-test-health';
  const verifierId = 'test-verifier-id';

  beforeAll(async () => {
    // TODO: get from the `authenticateRequest` function instead of using the mock
    authToken = generateMockAuthTokenForMetadataRequests({
      verifier,
      verifierId,
    });
  });

  it('should be able to initialize with default storage locations', () => {
    const metadataStore = new MetadataStore({
      authToken,
    });
    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe('metadata-server');
  });

  it('should be able to initialize with profile-sync storage location', () => {
    const metadataStore = new MetadataStore({
      authToken,
      storageLocation: MetadataStorageLocation.PROFILE_SYNC,
    });
    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe('profile-sync');
  });

  it('should throw an error if invalid metadata server url is provided', async () => {
    const metadataStore = new MetadataStore({
      metadataServerUrl: 'https://invalid-url',
      authToken,
    });

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', MOCK_SEED),
    ).rejects.toThrow(MetadataStoreError);

    await expect(metadataStore.fetchSecretData(MOCK_SEED)).rejects.toThrow(
      MetadataStoreError,
    );
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });
    const secretData = 'SECRET_DATA';

    await metadataStore.storeSecretData(secretData, MOCK_SEED);

    const result = await metadataStore.fetchSecretData(MOCK_SEED);
    expect(result).not.toBeNull();
    expect(result?.secretData[0]).toBe(secretData);
  });

  it('should be able to store/fetch data with different instances', async () => {
    const metadataStore1 = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });
    const metadataStore2 = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    const secretData = 'SECRET_DATA';

    await metadataStore1.storeSecretData(secretData, MOCK_SEED);

    const result = await metadataStore2.fetchSecretData(MOCK_SEED);

    expect(result).not.toBeNull();
    expect(result?.secretData[0]).toBe(secretData);
  });

  it('should be able to store secret data in batch', async () => {
    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    const newMockSeed = randomBytes(32);
    const secretDataArray = ['SECRET_DATA_1', 'SECRET_DATA_2'].sort();

    await metadataStore.storeSecretDataBatch(secretDataArray, newMockSeed);

    const result = await metadataStore.fetchSecretData(newMockSeed);
    expect(result).not.toBeNull();
    expect(result?.secretData.length).toBe(2);

    const sortedResult = result?.secretData.sort();

    expect(sortedResult?.[0]).toBe(secretDataArray[0]);
    expect(sortedResult?.[1]).toBe(secretDataArray[1]);
  });

  it('should be able to acquire/release lock', async () => {
    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    const lockId = await metadataStore.acquireMetadataLock(MOCK_SEED);
    expect(lockId).toBeDefined();

    const lockStatus = await metadataStore.releaseMetadataLock(
      MOCK_SEED,
      lockId,
    );
    expect(lockStatus).toBe(MetadataLockStatus.SUCCESS);
  });

  it('should fail to acquire lock if it is already acquired', async () => {
    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    const lockId = await metadataStore.acquireMetadataLock(MOCK_SEED);
    expect(lockId).toBeDefined();

    await expect(metadataStore.acquireMetadataLock(MOCK_SEED)).rejects.toThrow(
      'Failed to acquire metadata lock',
    );

    // release the lock
    const lockStatus = await metadataStore.releaseMetadataLock(
      MOCK_SEED,
      lockId,
    );
    expect(lockStatus).toBe(MetadataLockStatus.SUCCESS);
  });

  it('should throw an error if lockId is missing in the response', async () => {
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
          json: async () => Promise.resolve({ status: 1 }),
          // eslint-disable-next-line no-restricted-globals
        } as Response);
      });

    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    await expect(metadataStore.acquireMetadataLock(MOCK_SEED)).rejects.toThrow(
      'Failed to acquire metadata lock. Missing lock id',
    );

    expect(fetchSpy).toHaveBeenCalled();
    jest.restoreAllMocks();
  });

  it('should get empty array if metadata key not found', async () => {
    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    const randomSeed = randomBytes(32);
    const result = await metadataStore.fetchSecretData(randomSeed);
    expect(result?.secretData.length).toBe(0);
  });

  it('should return `null` if the data is not present in the metadata response', async () => {
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

    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    const result = await metadataStore.fetchSecretData(MOCK_SEED);

    expect(fetchSpy).toHaveBeenCalled();
    expect(result).toBeNull();

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

    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', MOCK_SEED),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.storeSecretDataBatch(
        ['SECRET_DATA_1', 'SECRET_DATA_2'],
        MOCK_SEED,
      ),
    ).rejects.toThrow('Something went wrong!');

    await expect(metadataStore.fetchSecretData(MOCK_SEED)).rejects.toThrow(
      'Something went wrong!',
    );

    await expect(metadataStore.acquireMetadataLock(MOCK_SEED)).rejects.toThrow(
      'Something went wrong!',
    );

    await expect(
      metadataStore.releaseMetadataLock(MOCK_SEED, 'LOCK_ID'),
    ).rejects.toThrow('Something went wrong!');

    expect(fetchSpy).toHaveBeenCalledTimes(5);

    jest.restoreAllMocks();
  });

  it('should handle if it fails to read the http error response', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        throw new Error();
      });

    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', MOCK_SEED),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.storeSecretDataBatch(
        ['SECRET_DATA_1', 'SECRET_DATA_2'],
        MOCK_SEED,
      ),
    ).rejects.toThrow('Unknown error');

    await expect(metadataStore.fetchSecretData(MOCK_SEED)).rejects.toThrow(
      'Unknown error',
    );

    await expect(metadataStore.acquireMetadataLock(MOCK_SEED)).rejects.toThrow(
      'Unknown error',
    );

    await expect(
      metadataStore.releaseMetadataLock(MOCK_SEED, 'LOCK_ID'),
    ).rejects.toThrow('Unknown error');

    expect(fetchSpy).toHaveBeenCalledTimes(5);

    jest.restoreAllMocks();
  });

  it('should not make network requests to metadata server if profile-sync storage location is used', async () => {
    const metadataStore = new MetadataStore({
      authToken,
      storageLocation: MetadataStorageLocation.PROFILE_SYNC,
    });

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', MOCK_SEED),
    ).rejects.toThrow('Metadata store is not using metadata server');

    await expect(metadataStore.fetchSecretData(MOCK_SEED)).rejects.toThrow(
      'Metadata store is not using metadata server',
    );
  });
});
