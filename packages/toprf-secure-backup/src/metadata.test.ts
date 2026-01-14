import { randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { TORUS_SAPPHIRE_NETWORK_TYPE } from '@toruslabs/constants';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';

import { EncAccountDataType } from './constants';
import type { KeyPair } from './interfaces';
import {
  deriveAuthenticationKeyPair,
  deriveEncryptionKey,
} from './keyDerivation';
import { MetadataLockStatus, MetadataStore } from './metadata';
import { createNodeEndpointsMap } from './utils';
import { generateMetadataAccessToken } from '../tests/testHelpers';

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
      verifier: 'auth-connection-id',
      verifierId: 'user-id',
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
  const userId = 'test-user';
  const fetchMetadataAccessCreds = generateMetadataAccessToken(userId);

  return new MetadataStore({
    metadataEndpoint: node1MetadataEndpoint,
    fetchMetadataAccessCreds,
  });
}

describe('MetadataStore', () => {
  let encKey: Uint8Array;
  let authKeyPair: KeyPair;

  beforeEach(async () => {
    // we gonna use different seeds for each test case
    const MOCK_SEED = randomBytes(32);
    encKey = deriveEncryptionKey(MOCK_SEED);
    authKeyPair = deriveAuthenticationKeyPair(MOCK_SEED);
  });

  it('should be able to store/fetch data', async () => {
    const metadataStore = await createMetadataStore();

    await metadataStore.addSecretDataItem({
      secretData: { data: secretData, dataType: EncAccountDataType.PrimarySrp },
      encKey,
      authKeyPair,
    });

    const result = await metadataStore.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
    );
    expect(result).not.toBeNull();
    expect(result?.[0].data).toStrictEqual(secretData);
    expect(result?.[0].dataType).toBe(EncAccountDataType.PrimarySrp);
    expect(result?.[0].version).toBe('v2');
    expect(result?.[0].createdAt).toBeDefined();

    // Add second item to test filtering by itemId
    await metadataStore.addSecretDataItem({
      secretData: {
        data: utf8ToBytes('data-2'),
        dataType: EncAccountDataType.ImportedSrp,
      },
      encKey,
      authKeyPair,
    });

    const allItems = await metadataStore.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
    );
    expect(allItems).toHaveLength(2);
    expect(allItems[0].data).toStrictEqual(secretData);
    expect(allItems[0].dataType).toBe(EncAccountDataType.PrimarySrp);
    expect(allItems[0].version).toBe('v2');
    expect(allItems[0].createdAt).toBeDefined();
    expect(allItems[1].data).toStrictEqual(utf8ToBytes('data-2'));
    expect(allItems[1].dataType).toBe(EncAccountDataType.ImportedSrp);
    expect(allItems[1].version).toBe('v2');
    expect(allItems[1].createdAt).toBeDefined();

    // Fetch with specific itemId - should filter out other items
    const filteredResult = await metadataStore.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
      allItems[0].itemId,
    );
    expect(filteredResult).toHaveLength(1);
    expect(filteredResult[0].itemId).toBe(allItems[0].itemId);
  });

  it('should be able to store/fetch data with different instances', async () => {
    const metadataStore1 = await createMetadataStore();
    const metadataStore2 = await createMetadataStore();

    await metadataStore1.addSecretDataItem({
      secretData: {
        data: secretData,
        dataType: EncAccountDataType.ImportedSrp,
      },
      encKey,
      authKeyPair,
    });

    const result = await metadataStore2.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
    );
    expect(result).not.toBeNull();
    expect(result?.[0].data).toStrictEqual(secretData);
    expect(result?.[0].dataType).toBe(EncAccountDataType.ImportedSrp);
    expect(result?.[0].version).toBe('v2');
    expect(result?.[0].createdAt).toBeDefined();
  });

  it('should be able to acquire and release metadata lock', async () => {
    const metadataStore = await createMetadataStore();

    const metadataLock = await metadataStore.acquireMetadataLock(authKeyPair);

    expect(metadataLock).not.toBeNull();

    const releaseLockStatus = await metadataStore.releaseMetadataLock(
      authKeyPair,
      metadataLock,
    );

    expect(releaseLockStatus).toStrictEqual(MetadataLockStatus.SUCCESS);
  });

  it('should fail to acquire lock if it is already acquired', async () => {
    const metadataStore = await createMetadataStore();

    const metadataLock = await metadataStore.acquireMetadataLock(authKeyPair);
    expect(metadataLock).toBeDefined();

    await expect(
      metadataStore.acquireMetadataLock(authKeyPair),
    ).rejects.toThrow('Failed to acquire metadata lock');

    // release the lock
    const lockStatus = await metadataStore.releaseMetadataLock(
      authKeyPair,
      metadataLock,
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

    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.acquireMetadataLock(authKeyPair),
    ).rejects.toThrow('Failed to acquire metadata lock. Missing lock id');

    expect(fetchSpy).toHaveBeenCalled();
    jest.restoreAllMocks();
  });

  it('should throw an error if releaseLock status is not success', async () => {
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
          json: async () => Promise.resolve({ success: false }),
          // eslint-disable-next-line no-restricted-globals
        } as Response);
      });

    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.releaseMetadataLock(authKeyPair, 'LOCK_ID_2'),
    ).rejects.toThrow('Failed to release metadata lock with id LOCK_ID_2');

    expect(fetchSpy).toHaveBeenCalled();
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

  it('should throw an error if the data is not present in the metadata response', async () => {
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

  it('should convert null createdAt from server to undefined', async () => {
    const metadataStore = await createMetadataStore();

    // Add real data first
    await metadataStore.addSecretDataItem({
      secretData: { data: secretData, dataType: EncAccountDataType.PrimarySrp },
      encKey,
      authKeyPair,
    });

    // Capture real response by intercepting fetch
    let capturedResponse: object = {};
    const originalFetch = global.fetch;
    const captureSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async (...args: unknown[]) => {
        const response = await originalFetch(
          args[0] as Parameters<typeof fetch>[0],
          args[1] as Parameters<typeof fetch>[1],
        );
        const clonedResponse = response.clone();
        capturedResponse = await clonedResponse.json();
        return response;
      });

    await metadataStore.fetchAllSecretDataItems(encKey, authKeyPair);
    captureSpy.mockRestore();

    // Now mock with captured data but null createdAt
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => {
        return Promise.resolve({
          ok: true,
          // eslint-disable-next-line jsdoc/require-jsdoc
          json: async () => ({ ...capturedResponse, createdAt: [null] }),
          // eslint-disable-next-line no-restricted-globals
        } as Response);
      });

    const result = await metadataStore.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
    );

    expect(result[0].createdAt).toBeUndefined();
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
        secretData: {
          data: utf8ToBytes('SECRET_DATA'),
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.acquireMetadataLock(authKeyPair),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.batchAddSecretData({
        secretData: [
          {
            data: utf8ToBytes('SECRET_DATA'),
            dataType: EncAccountDataType.PrimarySrp,
          },
        ],
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.releaseMetadataLock(authKeyPair, 'LOCK_ID_2'),
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
        secretData: {
          data: utf8ToBytes('SECRET_DATA'),
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.acquireMetadataLock(authKeyPair),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.batchAddSecretData({
        secretData: [
          {
            data: utf8ToBytes('SECRET_DATA'),
            dataType: EncAccountDataType.PrimarySrp,
          },
        ],
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.releaseMetadataLock(authKeyPair, 'LOCK_ID_2'),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.fetchAllSecretDataItems(encKey, authKeyPair),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.updateSecretDataItem({
        updateItem: {
          itemId: 'test-item',
          fields: { dataType: EncAccountDataType.PrimarySrp },
        },
        authKeyPair,
      }),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.batchUpdateSecretData({
        updateItems: [
          {
            itemId: 'test-item',
            fields: { dataType: EncAccountDataType.PrimarySrp },
          },
        ],
        authKeyPair,
      }),
    ).rejects.toThrow('Unknown error');

    expect(fetchSpy).toHaveBeenCalled();

    jest.restoreAllMocks();
  });

  it('should be able to store and retrieve pw backup item', async () => {
    const metadataStore = await createMetadataStore();

    await metadataStore.addSecretDataItem({
      secretData: { data: secretData, itemId: 'PW_BACKUP' },
      encKey,
      authKeyPair,
    });

    const result = await metadataStore.fetchAllSecretDataItems(
      encKey,
      authKeyPair,
      'PW_BACKUP',
    );

    expect(result).not.toBeNull();
    expect(result?.length).toBe(1);
    expect(result?.[0].data).toStrictEqual(secretData);
    expect(result?.[0].itemId).toBe('PW_BACKUP');
  });

  it('should reject dataType for PW_BACKUP inserts', async () => {
    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.addSecretDataItem({
        secretData: {
          data: secretData,
          itemId: 'PW_BACKUP',
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('dataType cannot be set for PW_BACKUP item');
  });

  it('should require dataType for v2 secret data items', async () => {
    const metadataStore = await createMetadataStore();

    // Single add: Default version (v2) should require dataType
    await expect(
      metadataStore.addSecretDataItem({
        secretData: { data: secretData },
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('dataType is required for v2 secret data items');

    // Single add: Explicit v2 should require dataType
    await expect(
      metadataStore.addSecretDataItem({
        secretData: { data: secretData, version: 'v2' },
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('dataType is required for v2 secret data items');

    // Batch add: Default version (v2) should require dataType
    const lockId = await metadataStore.acquireMetadataLock(authKeyPair);
    await expect(
      metadataStore.batchAddSecretData({
        secretData: [{ data: secretData }],
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('dataType is required for v2 secret data items');

    // Batch add: Explicit v2 should require dataType
    await expect(
      metadataStore.batchAddSecretData({
        secretData: [{ data: secretData, version: 'v2' }],
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('dataType is required for v2 secret data items');
    await metadataStore.releaseMetadataLock(authKeyPair, lockId);
  });

  describe('batchAddSecretData', () => {
    it('should be able to store secret data in batch', async () => {
      const metadataStore = await createMetadataStore();

      await metadataStore.addSecretDataItem({
        secretData: {
          data: secretData,
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      });

      const allSecretDataBeforeBatchAdd =
        await metadataStore.fetchAllSecretDataItems(encKey, authKeyPair);
      expect(allSecretDataBeforeBatchAdd).not.toBeNull();
      expect(allSecretDataBeforeBatchAdd?.[0].dataType).toBe(
        EncAccountDataType.PrimarySrp,
      );

      // derive new encryption key and authentication key pair from the new seed
      const newSeed = randomBytes(32);
      const newEncKey = deriveEncryptionKey(newSeed);
      const newAuthKeyPair = deriveAuthenticationKeyPair(newSeed);

      // acquire the metadata lock
      const metadataLock =
        await metadataStore.acquireMetadataLock(newAuthKeyPair);
      expect(metadataLock).not.toBeNull();

      await metadataStore.batchAddSecretData({
        secretData: allSecretDataBeforeBatchAdd ?? [], // should not be null, the above `expect` should have failed if it was
        encKey: newEncKey,
        authKeyPair: newAuthKeyPair,
      });

      // the result should be the new encrypted value of the existing secret data
      const allSecretDataAfterBatchAdd =
        await metadataStore.fetchAllSecretDataItems(newEncKey, newAuthKeyPair);

      // Verify secretData values before/after batchAdd are equal
      expect(allSecretDataAfterBatchAdd).not.toBeNull();
      expect(allSecretDataAfterBatchAdd?.length).toStrictEqual(
        allSecretDataBeforeBatchAdd?.length,
      );

      const sortedResult = allSecretDataAfterBatchAdd?.sort();
      const shouldHaveSameValuesBeforeAfterBatchAdd = sortedResult.every(
        (dataAfterBatch, idx) => {
          const dataBeforeBatchAdd = allSecretDataBeforeBatchAdd?.[idx];
          if (!dataBeforeBatchAdd) {
            return false;
          }
          return (
            Buffer.from(dataAfterBatch.data).equals(
              Buffer.from(dataBeforeBatchAdd.data),
            ) && dataAfterBatch.dataType === dataBeforeBatchAdd.dataType
          );
        },
      );
      expect(shouldHaveSameValuesBeforeAfterBatchAdd).toBe(true);

      // Verify all items have version v2 and createdAt
      allSecretDataAfterBatchAdd?.forEach((item) => {
        expect(item.version).toBe('v2');
        expect(item.createdAt).toBeDefined();
      });

      // release the metadata lock
      const releaseLockStatus = await metadataStore.releaseMetadataLock(
        newAuthKeyPair,
        metadataLock,
      );

      expect(releaseLockStatus).toStrictEqual(MetadataLockStatus.SUCCESS);
    });

    it('should throw error if length of secretData and encKey are not equal', async () => {
      const metadataStore = await createMetadataStore();

      await expect(
        metadataStore.batchAddSecretData({
          secretData: [
            {
              data: utf8ToBytes('SECRET_DATA'),
              dataType: EncAccountDataType.PrimarySrp,
            },
          ],
          encKey: [encKey, encKey], // length of secretData is 1, but encKey is 2
          authKeyPair,
        }),
      ).rejects.toThrow('encKey must be of same length as secretData');
    });

    it('should reject dataType for PW_BACKUP in batch inserts', async () => {
      const metadataStore = await createMetadataStore();

      await expect(
        metadataStore.batchAddSecretData({
          secretData: [
            {
              data: utf8ToBytes('DATA_1'),
              dataType: EncAccountDataType.PrimarySrp,
            },
            {
              data: utf8ToBytes('DATA_2'),
              itemId: 'PW_BACKUP',
              dataType: EncAccountDataType.ImportedSrp,
            },
          ],
          encKey,
          authKeyPair,
        }),
      ).rejects.toThrow('dataType cannot be set for PW_BACKUP item');
    });
  });

  describe('updateSecretDataItem', () => {
    it('should update fields for existing item', async () => {
      const metadataStore = await createMetadataStore();

      // Add legacy data (v1) without dataType - simulates old data that needs migration
      await metadataStore.addSecretDataItem({
        secretData: { data: secretData, version: 'v1' },
        encKey,
        authKeyPair,
      });

      const beforeUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(beforeUpdate).toHaveLength(1);
      expect(beforeUpdate[0].data).toStrictEqual(secretData);
      expect(beforeUpdate[0].dataType).toBeUndefined();
      expect(beforeUpdate[0].version).toBe('v1');
      expect(beforeUpdate[0].createdAt).toBeDefined();
      expect(beforeUpdate[0].itemId).toBeDefined();

      await metadataStore.updateSecretDataItem({
        updateItem: {
          itemId: beforeUpdate[0].itemId,
          fields: { dataType: EncAccountDataType.PrimarySrp },
        },
        authKeyPair,
      });

      const afterUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(afterUpdate).toHaveLength(1);
      expect(afterUpdate[0].data).toStrictEqual(secretData);
      expect(afterUpdate[0].dataType).toBe(EncAccountDataType.PrimarySrp);
      expect(afterUpdate[0].version).toBe('v2');
      expect(afterUpdate[0].createdAt).toBeDefined();
    });

    it('should handle HTTP error response', async () => {
      const metadataStore = await createMetadataStore();

      const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue({
        ok: false,
        // eslint-disable-next-line jsdoc/require-jsdoc
        json: async () => ({ error: 'Server error' }),
      } as globalThis.Response);

      await expect(
        metadataStore.updateSecretDataItem({
          updateItem: {
            itemId: 'some-item-id',
            fields: { dataType: EncAccountDataType.PrimarySrp },
          },
          authKeyPair,
        }),
      ).rejects.toThrow('HTTP error message: Server error');

      fetchSpy.mockRestore();
    });

    it('should reject PW_BACKUP update', async () => {
      const metadataStore = await createMetadataStore();

      await expect(
        metadataStore.updateSecretDataItem({
          updateItem: {
            itemId: 'PW_BACKUP',
            fields: { dataType: EncAccountDataType.PrimarySrp },
          },
          authKeyPair,
        }),
      ).rejects.toThrow('PW_BACKUP cannot be updated');
    });
  });

  describe('batchUpdateSecretData', () => {
    it('should batch update fields for existing items', async () => {
      const metadataStore = await createMetadataStore();

      const data1 = utf8ToBytes('DATA_1');
      const data2 = utf8ToBytes('DATA_2');

      // Add legacy data (v1) without dataType - simulates old data that needs migration
      let lockId = await metadataStore.acquireMetadataLock(authKeyPair);
      await metadataStore.batchAddSecretData({
        secretData: [
          { data: data1, version: 'v1' },
          { data: data2, version: 'v1' },
        ],
        encKey,
        authKeyPair,
      });
      await metadataStore.releaseMetadataLock(authKeyPair, lockId);

      const beforeUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(beforeUpdate).toHaveLength(2);
      expect(beforeUpdate[0].data).toStrictEqual(data1);
      expect(beforeUpdate[0].dataType).toBeUndefined();
      expect(beforeUpdate[0].version).toBe('v1');
      expect(beforeUpdate[0].createdAt).toBeDefined();
      expect(beforeUpdate[0].itemId).toBeDefined();
      expect(beforeUpdate[1].data).toStrictEqual(data2);
      expect(beforeUpdate[1].dataType).toBeUndefined();
      expect(beforeUpdate[1].version).toBe('v1');
      expect(beforeUpdate[1].createdAt).toBeDefined();
      expect(beforeUpdate[1].itemId).toBeDefined();

      lockId = await metadataStore.acquireMetadataLock(authKeyPair);
      await metadataStore.batchUpdateSecretData({
        updateItems: [
          {
            itemId: beforeUpdate[0].itemId,
            fields: { dataType: EncAccountDataType.PrimarySrp },
          },
          {
            itemId: beforeUpdate[1].itemId,
            fields: { dataType: EncAccountDataType.ImportedSrp },
          },
        ],
        authKeyPair,
      });
      await metadataStore.releaseMetadataLock(authKeyPair, lockId);

      const afterUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(afterUpdate).toHaveLength(2);

      const item1 = afterUpdate.find(
        (item) => item.itemId === beforeUpdate[0].itemId,
      );
      const item2 = afterUpdate.find(
        (item) => item.itemId === beforeUpdate[1].itemId,
      );

      expect(item1?.data).toStrictEqual(data1);
      expect(item1?.dataType).toBe(EncAccountDataType.PrimarySrp);
      expect(item1?.version).toBe('v2');
      expect(item1?.createdAt).toBeDefined();
      expect(item2?.data).toStrictEqual(data2);
      expect(item2?.dataType).toBe(EncAccountDataType.ImportedSrp);
      expect(item2?.version).toBe('v2');
      expect(item2?.createdAt).toBeDefined();
    });

    it('should reject PW_BACKUP from itemId-only update path', async () => {
      const metadataStore = await createMetadataStore();

      await expect(
        metadataStore.batchUpdateSecretData({
          updateItems: [
            {
              itemId: 'item-1',
              fields: { dataType: EncAccountDataType.PrimarySrp },
            },
            {
              itemId: 'PW_BACKUP',
              fields: { dataType: EncAccountDataType.ImportedSrp },
            },
          ],
          authKeyPair,
        }),
      ).rejects.toThrow('PW_BACKUP cannot be updated');
    });

    it('should handle HTTP error response', async () => {
      const metadataStore = await createMetadataStore();

      const fetchSpy = jest.spyOn(globalThis, 'fetch').mockResolvedValue({
        ok: false,
        // eslint-disable-next-line jsdoc/require-jsdoc
        json: async () => ({ error: 'Batch update failed' }),
      } as globalThis.Response);

      await expect(
        metadataStore.batchUpdateSecretData({
          updateItems: [
            {
              itemId: 'some-item-id',
              fields: { dataType: EncAccountDataType.PrimarySrp },
            },
          ],
          authKeyPair,
        }),
      ).rejects.toThrow('HTTP error message: Batch update failed');

      fetchSpy.mockRestore();
    });
  });
});
