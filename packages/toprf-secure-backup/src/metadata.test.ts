import { randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { TORUS_SAPPHIRE_NETWORK_TYPE } from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import type { KeyPair } from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataStore } from './metadata';
import { createNodeEndpointsMap } from './utils';

const MOCK_SEED = randomBytes(32);
const secretData = utf8ToBytes('test-secret-data');

/**
 * Gets the node endpoints map.
 *
 * @param network - The network to get the node endpoints map for.
 *
 * @returns The node endpoints map.
 */
async function getNodeEndpointsMap(
  network: TORUS_SAPPHIRE_NETWORK_TYPE = 'sapphire_devnet',
): Promise<{ [nodeIndex: string]: string }> {
  const nodeDetailManager = new NodeDetailManager({
    network,
  });
  const { torusNodeSSSEndpoints, torusIndexes } =
    await nodeDetailManager.getNodeDetails({
      verifier: 'DEFAULT_VERIFIER',
      verifierId: 'DEFAULT_VERIFIER_ID',
    });
  if (!torusNodeSSSEndpoints || !torusIndexes) {
    throw new Error('Failed to get node details');
  }
  const nodeEndpointsMap = createNodeEndpointsMap(
    torusNodeSSSEndpoints,
    torusIndexes,
  );
  const metadataEndpointsMap: { [nodeIndex: string]: string } = {};
  Object.entries(nodeEndpointsMap).forEach(([key, value]) => {
    const url = new URL(value);
    metadataEndpointsMap[key] = `${url.origin}/metadata`;
  });
  return metadataEndpointsMap;
}

/**
 * Creates a mock MetadataStore instance.
 *
 * @param nodeEndpointsMap - The map of node endpoints which includes node index as key and node endpoint as value.
 * @returns A mock MetadataStore instance.
 */
async function createMetadataStore(nodeEndpointsMap?: {
  [nodeIndex: string]: string;
}): Promise<MetadataStore> {
  let nodeEndpoints = nodeEndpointsMap;
  nodeEndpoints ??= await getNodeEndpointsMap();
  const node1MetadataEndpoint = nodeEndpoints['1'];

  return new MetadataStore({ metadataEndpoint: node1MetadataEndpoint });
}

describe('MetadataStore', () => {
  let encKey: Uint8Array;
  let authKeyPair: KeyPair;

  beforeAll(async () => {
    encKey = deriveEncryptionKey(MOCK_SEED);
    authKeyPair = deriveAuthenticationKeyPair(MOCK_SEED);
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = await createMetadataStore();

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
    const metadataStore1 = await createMetadataStore();
    const metadataStore2 = await createMetadataStore();

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

  it('should get empty array if metadata key not found', async () => {
    const metadataStore = await createMetadataStore();

    const randomSeed = randomBytes(32);
    const randomAuthKeyPair = deriveAuthenticationKeyPair(randomSeed);
    const result = await metadataStore.fetchAllSecretDataItems(
      deriveEncryptionKey(randomSeed),
      randomAuthKeyPair,
    );
    expect(result).not.toBeNull();
    expect(result?.length).toBe(0);
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

    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Failed to fetch metadata');

    expect(fetchSpy).toHaveBeenCalled();

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

    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.addSecretDataItem({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Something went wrong!');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });

  it('should handle if it fails to read the http error response', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        throw new Error();
      });

    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.addSecretDataItem({
        secretData: utf8ToBytes('SECRET_DATA'),
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Unknown error');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });
});
