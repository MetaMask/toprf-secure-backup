import { randomBytes } from '@noble/hashes/utils';

import type { KeyPair, NodeAuthTokens } from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataStorageLocation, MetadataStore } from './metadata';
import { generateMockAuthTokenForMetadataRequests } from '../tests/metadata-utils';

const MOCK_SEED = randomBytes(32);
const METADATA_SERVER_URL = 'http://localhost:5051';
const NODE_INDEXES = [1, 2, 3];

/**
 * Creates a mock MetadataStore instance.
 *
 * @param authTokens - The authentication tokens for the metadata store.
 * @param nodeEndpoints - The endpoints of the nodes for the metadata store.
 * @param nodeIndexes - The indexes of the nodes for the metadata store.
 * @returns A mock MetadataStore instance.
 */
function mockMetadataStoreFactory(
  authTokens: NodeAuthTokens,
  nodeEndpoints = [
    METADATA_SERVER_URL,
    METADATA_SERVER_URL,
    METADATA_SERVER_URL,
  ],
  nodeIndexes = NODE_INDEXES,
): MetadataStore {
  return new MetadataStore({ authTokens, nodeEndpoints, nodeIndexes });
}

describe('MetadataStore', () => {
  let authTokens: NodeAuthTokens;
  let encKey: Uint8Array;
  let authKeyPair: KeyPair;
  const verifier = 'torus-test-health';
  const verifierId = 'test-verifier-id';

  beforeAll(async () => {
    // TODO: get from the `authenticateRequest` function instead of using the mock
    authTokens = generateMockAuthTokenForMetadataRequests({
      verifier,
      verifierId,
    });
    encKey = deriveEncryptionKey(MOCK_SEED);
    const authenticationKeyPair = deriveAuthenticationKeyPair(MOCK_SEED);
    authKeyPair = {
      privKey: authenticationKeyPair.sk,
      pubKey: authenticationKeyPair.pk,
    };
  });

  it('should throw an error if invalid nodeEndpoints and nodeIndexes are provided for metadata server', () => {
    expect(() => new MetadataStore({ authTokens })).toThrow(
      'nodeEndpoints and nodeIndexes are required for metadata server',
    );

    expect(
      () =>
        new MetadataStore({
          authTokens,
          nodeEndpoints: [METADATA_SERVER_URL],
          nodeIndexes: [],
        }),
    ).toThrow('nodeEndpoints and nodeIndexes must have the same length');
  });

  it('should be able to initialize with default storage location', () => {
    const metadataStore = new MetadataStore({
      authTokens,
      nodeEndpoints: [METADATA_SERVER_URL],
      nodeIndexes: [0],
    });

    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe(
      MetadataStorageLocation.METADATA_SERVER,
    );
  });

  it('should be able to initialize with profile-sync storage location', () => {
    const metadataStore = new MetadataStore({
      authTokens,
      storageLocation: MetadataStorageLocation.PROFILE_SYNC,
    });
    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe('profile-sync');
  });

  it('should throw an error if valid `authToken` cannot be found with the given nodeIndex', async () => {
    const metadataStore = new MetadataStore({
      authTokens,
      nodeEndpoints: [METADATA_SERVER_URL],
      nodeIndexes: [4],
    });

    await expect(async () =>
      metadataStore.storeSecretData('SECRET_DATA', encKey, authKeyPair),
    ).rejects.toThrow('Auth token not found for node index: 4');
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = mockMetadataStoreFactory(authTokens);
    const secretData = 'SECRET_DATA';

    await metadataStore.storeSecretData(secretData, encKey, authKeyPair);

    const result = await metadataStore.fetchSecretData(encKey, authKeyPair);
    expect(result).not.toBeNull();
    expect(result?.secretData[0]).toBe(secretData);
  });

  it('should be able to store/fetch data with different instances', async () => {
    const metadataStore1 = mockMetadataStoreFactory(authTokens);
    const metadataStore2 = mockMetadataStoreFactory(authTokens);

    const secretData = 'SECRET_DATA';

    await metadataStore1.storeSecretData(secretData, encKey, authKeyPair);

    const result = await metadataStore2.fetchSecretData(encKey, authKeyPair);

    expect(result).not.toBeNull();
    expect(result?.secretData[0]).toBe(secretData);
  });

  it('should get null if metadata key not found', async () => {
    const metadataStore = mockMetadataStoreFactory(authTokens);

    const randomSeed = randomBytes(32);
    const { sk, pk } = deriveAuthenticationKeyPair(randomSeed);
    const randomAuthKeyPair = {
      privKey: sk,
      pubKey: pk,
    };
    const result = await metadataStore.fetchSecretData(
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

    const metadataStore = mockMetadataStoreFactory(authTokens);

    await expect(
      metadataStore.fetchSecretData(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });

  it('should throw an error if the threshold is not met', async () => {
    const metadataStore = new MetadataStore({
      authTokens,
      nodeEndpoints: [
        'https://metadata-server.toprf.xyz/node-1',
        'https://metadata-server.toprf.xyz/node-2',
        'https://metadata-server.toprf.xyz/node-3',
      ],
      nodeIndexes: [1, 2, 3],
    });

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
      metadataStore.fetchSecretData(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalledTimes(3);
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

    const metadataStore = mockMetadataStoreFactory(authTokens);

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', encKey, authKeyPair),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.fetchSecretData(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalledTimes(2 * NODE_INDEXES.length);

    jest.restoreAllMocks();
  });

  it('should handle if it fails to read the http error response', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        throw new Error();
      });

    const metadataStore = mockMetadataStoreFactory(authTokens);

    await expect(
      metadataStore.storeSecretData('SECRET_DATA', encKey, authKeyPair),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.fetchSecretData(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalledTimes(2 * NODE_INDEXES.length);

    jest.restoreAllMocks();
  });
});
