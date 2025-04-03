import { randomBytes, utf8ToBytes } from '@noble/hashes/utils';

import type { KeyPair, NodeAuthTokens } from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataStorageLocation, MetadataStore } from './metadata';
import { generateMockAuthTokenForMetadataRequests } from '../tests/metadata-utils';

const MOCK_SEED = randomBytes(32);
const METADATA_SERVER_URL = 'http://localhost:5051';
const NODE_ENDPOINTS_MAP = new Map([
  [1, METADATA_SERVER_URL],
  [2, METADATA_SERVER_URL],
  [3, METADATA_SERVER_URL],
]);

/**
 * Creates a mock MetadataStore instance.
 *
 * @param nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
 * @returns A mock MetadataStore instance.
 */
function createMockMetadataStore(
  nodeEndpointsMap: Map<number, string> = NODE_ENDPOINTS_MAP,
): MetadataStore {
  return new MetadataStore({ nodeEndpointsMap });
}

describe('MetadataStore', () => {
  let nodeAuthTokens: NodeAuthTokens;
  let encKey: Uint8Array;
  let authKeyPair: KeyPair;
  const verifier = 'torus-test-health';
  const verifierId = 'test-verifier-id';

  beforeAll(async () => {
    // TODO: get from the `authenticateRequest` function instead of using the mock
    nodeAuthTokens = generateMockAuthTokenForMetadataRequests({
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

  it('should throw an error if invalid nodeEndpointsMap is provided for metadata server', () => {
    expect(() => new MetadataStore()).toThrow(
      'nodeEndpointsMap is required for metadata server',
    );
  });

  it('should be able to initialize with default storage location', () => {
    const metadataStore = new MetadataStore({
      nodeEndpointsMap: NODE_ENDPOINTS_MAP,
    });

    expect(metadataStore).toBeDefined();
    expect(metadataStore.metadataStorageLocation).toBe(
      MetadataStorageLocation.MetadataServer,
    );
  });

  it('should throw an error if endpoint is not found for the node auth token', async () => {
    const metadataStore = new MetadataStore({
      nodeEndpointsMap: new Map([[3, 'http://localhost:5051']]),
    });

    await expect(async () =>
      metadataStore.storeSecretData({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
        nodeAuthTokens,
      }),
    ).rejects.toThrow('Endpoint not found for node index: 1');
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = createMockMetadataStore();
    const secretData = utf8ToBytes('SECRET_DATA');

    await metadataStore.storeSecretData({
      secretData,
      encKey,
      authKeyPair,
      nodeAuthTokens,
    });

    const result = await metadataStore.fetchSecretData(encKey, authKeyPair);
    expect(result).not.toBeNull();
    expect(result?.[0]).toStrictEqual(secretData);
  });

  it('should be able to store/fetch data with different instances', async () => {
    const metadataStore1 = createMockMetadataStore();
    const metadataStore2 = createMockMetadataStore();

    const secretData = utf8ToBytes('SECRET_DATA');

    await metadataStore1.storeSecretData({
      secretData,
      encKey,
      authKeyPair,
      nodeAuthTokens,
    });

    const result = await metadataStore2.fetchSecretData(encKey, authKeyPair);
    expect(result).not.toBeNull();
    expect(result?.[0]).toStrictEqual(secretData);
  });

  it('should get null if metadata key not found', async () => {
    const metadataStore = createMockMetadataStore();

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

    const metadataStore = createMockMetadataStore();

    await expect(
      metadataStore.fetchSecretData(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });

  it('should throw an error if the threshold is not met', async () => {
    const metadataStore = new MetadataStore({
      nodeEndpointsMap: NODE_ENDPOINTS_MAP,
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

    const metadataStore = createMockMetadataStore();

    await expect(
      metadataStore.storeSecretData({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
        nodeAuthTokens,
      }),
    ).rejects.toThrow('Threshold not resolved');

    await expect(
      metadataStore.fetchSecretData(encKey, authKeyPair),
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
      metadataStore.storeSecretData({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
        nodeAuthTokens,
      }),
    ).rejects.toThrow('Threshold not resolved');

    await expect(
      metadataStore.fetchSecretData(encKey, authKeyPair),
    ).rejects.toThrow('Threshold not resolved');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });
});
