import { randomBytes } from '@noble/hashes/utils';

import {
  MetadataStorageLocation,
  MetadataStore,
  MetadataStoreError,
} from './metadata';
import { generateMockAuthTokenForMetadataRequests } from '../tests/metadata-utils';

const MOCK_SEED = randomBytes(32);
const METADATA_SERVER_URL = 'http://localhost:5051/enc_account_data';
// const MOCK_AUTH_TOKEN =
//   'eyJ2ZXJpZmllciI6Im1vY2stdmVyaWZpZXIiLCJ2ZXJpZmllcl9pZCI6Im1vY2stdmVyaWZpZXItaWQiLCJhdWQiOiIxMGQyODAzOGU4NDA4MjllODdkOWFlMDA0OWM3MzgyZmRjYzE0Yzc0OWYyYWJiN2IwZjAxMTQxOTY2ZDZjNDIxIiwic2NvcGUiOiJtb2NrLXNjb3BlIiwidGVtcF9rZXlfeCI6Im1vY2stdGVtcC1rZXkteCIsInRlbXBfa2V5X3kiOiJtb2NrLXRlbXAta2V5LXkiLCJleHAiOjE4MDAwMDAwMDAsInNpZ25hdHVyZSI6IjEyYzMwYjEyMjIyOWQwYjhiZmY4YjcyODRiYmVmYzRlNjAyZDNiYTA3MTE1ODdmZGQxYThjN2FlOTEwNmE1NDBmZTZhNWE1NDM0MzBkMWMwOWRlN2Q1MWUxZWFhY2Y1ZWQyYmY4YzJiNWY0NjkwODMxMTk1Yzk1MjdjNzIwMjYyMDAifQ==';

describe('MetadatStore', () => {
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

    const metadataStore = new MetadataStore({
      authToken,
      metadataServerUrl: METADATA_SERVER_URL,
    });

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', MOCK_SEED),
    ).rejects.toThrow('Something went wrong!');

    expect(fetchSpy).toHaveBeenCalled();

    await expect(metadataStore.fetchSecretData(MOCK_SEED)).rejects.toThrow(
      'Something went wrong!',
    );

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
