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
    expect(result?.[0].createdAt).toBeDefined();
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
        secretData: { data: utf8ToBytes('SECRET_DATA') },
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
        secretData: [{ data: utf8ToBytes('SECRET_DATA') }],
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.releaseMetadataLock(authKeyPair, 'LOCK_ID_2'),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.deleteSecretDataItem('test-item-id', authKeyPair),
    ).rejects.toThrow('Something went wrong!');

    await expect(
      metadataStore.batchDeleteSecretDataItems(
        ['test-item-id-1', 'test-item-id-2'],
        authKeyPair,
      ),
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
        secretData: { data: utf8ToBytes('SECRET_DATA') },
        encKey,
        authKeyPair,
      }),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.acquireMetadataLock(authKeyPair),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.batchAddSecretData({
        secretData: [{ data: utf8ToBytes('SECRET_DATA') }],
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
      metadataStore.deleteSecretDataItem('test-item-id', authKeyPair),
    ).rejects.toThrow('Unknown error');

    await expect(
      metadataStore.batchDeleteSecretDataItems(
        ['test-item-id-1', 'test-item-id-2'],
        authKeyPair,
      ),
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

  it('should reject PW_BACKUP from itemId-only update path', async () => {
    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.updateSecretDataItem({
        updateItem: {
          itemId: 'PW_BACKUP',
          fields: { dataType: EncAccountDataType.PrimarySrp },
        },
        authKeyPair,
      }),
    ).rejects.toThrow('PW_BACKUP cannot be updated via itemId-only path');
  });

  it('should reject update without any fields', async () => {
    const metadataStore = await createMetadataStore();

    await expect(
      metadataStore.updateSecretDataItem({
        updateItem: {
          itemId: 'some-item-id',
          fields: {},
        },
        authKeyPair,
      }),
    ).rejects.toThrow('At least one field must be provided for update');
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

      // Verify all items have createdAt
      allSecretDataAfterBatchAdd?.forEach((item) => {
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
          secretData: [{ data: utf8ToBytes('SECRET_DATA') }],
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

      await metadataStore.addSecretDataItem({
        secretData: { data: secretData },
        encKey,
        authKeyPair,
      });

      const beforeUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(beforeUpdate?.length).toBe(1);
      const itemId = beforeUpdate?.[0].itemId;
      expect(itemId).toBeDefined();
      expect(beforeUpdate?.[0].dataType).toBeUndefined();

      await metadataStore.updateSecretDataItem({
        updateItem: {
          itemId: itemId as string,
          fields: { dataType: EncAccountDataType.PrimarySrp },
        },
        authKeyPair,
      });

      const afterUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(afterUpdate?.length).toBe(1);
      expect(afterUpdate?.[0].dataType).toBe(EncAccountDataType.PrimarySrp);
      expect(afterUpdate?.[0].data).toStrictEqual(secretData);
    });
  });

  describe('batchUpdateSecretData', () => {
    it('should batch update fields for existing items', async () => {
      const metadataStore = await createMetadataStore();

      const data1 = utf8ToBytes('DATA_1');
      const data2 = utf8ToBytes('DATA_2');

      let lockId = await metadataStore.acquireMetadataLock(authKeyPair);
      await metadataStore.batchAddSecretData({
        secretData: [{ data: data1 }, { data: data2 }],
        encKey,
        authKeyPair,
      });
      await metadataStore.releaseMetadataLock(authKeyPair, lockId);

      const beforeUpdate = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(beforeUpdate?.length).toBe(2);
      expect(beforeUpdate?.[0].dataType).toBeUndefined();
      expect(beforeUpdate?.[1].dataType).toBeUndefined();

      lockId = await metadataStore.acquireMetadataLock(authKeyPair);
      await metadataStore.batchUpdateSecretData({
        updateItems: [
          {
            itemId: beforeUpdate?.[0].itemId as string,
            fields: { dataType: EncAccountDataType.PrimarySrp },
          },
          {
            itemId: beforeUpdate?.[1].itemId as string,
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
      expect(afterUpdate?.length).toBe(2);

      const item1 = afterUpdate?.find(
        (item) => item.itemId === beforeUpdate?.[0].itemId,
      );
      const item2 = afterUpdate?.find(
        (item) => item.itemId === beforeUpdate?.[1].itemId,
      );

      expect(item1?.dataType).toBe(EncAccountDataType.PrimarySrp);
      expect(item2?.dataType).toBe(EncAccountDataType.ImportedSrp);
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
      ).rejects.toThrow('PW_BACKUP cannot be updated via itemId-only path');
    });

    it('should reject update without any fields in batch', async () => {
      const metadataStore = await createMetadataStore();

      await expect(
        metadataStore.batchUpdateSecretData({
          updateItems: [
            {
              itemId: 'item-1',
              fields: { dataType: EncAccountDataType.PrimarySrp },
            },
            { itemId: 'item-2', fields: {} },
          ],
          authKeyPair,
        }),
      ).rejects.toThrow('At least one field must be provided for update');
    });
  });

  describe('deleteSecretDataItem', () => {
    it('should be able to delete a non-PRIMARY_SRP secret data item', async () => {
      const metadataStore = await createMetadataStore();

      // Add PRIMARY_SRP item first
      await metadataStore.addSecretDataItem({
        secretData: {
          data: secretData,
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      // Add IMPORTED_SRP item second
      const secondSecretData = utf8ToBytes('second-test-secret-data');
      await metadataStore.addSecretDataItem({
        secretData: {
          data: secondSecretData,
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

      // Server returns items sorted by createdAt (oldest first after PRIMARY_SRP)
      // The last item in the array is the newest (IMPORTED_SRP)
      const newestItem = allItems[allItems.length - 1];

      await metadataStore.deleteSecretDataItem(
        newestItem.itemId as string,
        authKeyPair,
      );

      const remainingItems = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(remainingItems).toHaveLength(1);
      expect(remainingItems[0].itemId).not.toBe(newestItem.itemId);
    });

    it('should reject deleting the PRIMARY_SRP item', async () => {
      const metadataStore = await createMetadataStore();

      await metadataStore.addSecretDataItem({
        secretData: {
          data: secretData,
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      });

      const allItems = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(allItems).toHaveLength(1);

      const primarySrpItemId = allItems[0].itemId;

      await expect(
        metadataStore.deleteSecretDataItem(
          primarySrpItemId as string,
          authKeyPair,
        ),
      ).rejects.toThrow('Cannot delete the PRIMARY_SRP item');
    });
  });

  describe('batchDeleteSecretDataItems', () => {
    it('should be able to batch delete non-PRIMARY_SRP secret data items', async () => {
      const metadataStore = await createMetadataStore();

      // Add PRIMARY_SRP item first
      await metadataStore.addSecretDataItem({
        secretData: {
          data: secretData,
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      // Add IMPORTED_SRP items
      await metadataStore.addSecretDataItem({
        secretData: {
          data: utf8ToBytes('second-data'),
          dataType: EncAccountDataType.ImportedSrp,
        },
        encKey,
        authKeyPair,
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      await metadataStore.addSecretDataItem({
        secretData: {
          data: utf8ToBytes('third-data'),
          dataType: EncAccountDataType.ImportedSrp,
        },
        encKey,
        authKeyPair,
      });

      const allItems = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(allItems).toHaveLength(3);

      // Server returns items sorted: PRIMARY_SRP first, then by createdAt (oldest first)
      // Find the PRIMARY_SRP item to keep
      const primarySrpItem = allItems.find(
        (item) => item.dataType === EncAccountDataType.PrimarySrp,
      );
      if (!primarySrpItem) {
        throw new Error('PRIMARY_SRP item not found');
      }

      const itemIdsToDelete = allItems
        .filter((item) => item.itemId !== primarySrpItem.itemId)
        .map((item) => item.itemId) as string[];
      expect(itemIdsToDelete).toHaveLength(2);

      const lockId = await metadataStore.acquireMetadataLock(authKeyPair);
      await metadataStore.batchDeleteSecretDataItems(
        itemIdsToDelete,
        authKeyPair,
      );
      await metadataStore.releaseMetadataLock(authKeyPair, lockId);

      const remainingItems = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      expect(remainingItems).toHaveLength(1);
      expect(remainingItems[0].itemId).toBe(primarySrpItem.itemId);
    });

    it('should reject batch deleting if it includes the PRIMARY_SRP item', async () => {
      const metadataStore = await createMetadataStore();

      // Add PRIMARY_SRP item
      await metadataStore.addSecretDataItem({
        secretData: {
          data: secretData,
          dataType: EncAccountDataType.PrimarySrp,
        },
        encKey,
        authKeyPair,
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      // Add IMPORTED_SRP item
      await metadataStore.addSecretDataItem({
        secretData: {
          data: utf8ToBytes('second-data'),
          dataType: EncAccountDataType.ImportedSrp,
        },
        encKey,
        authKeyPair,
      });

      const allItems = await metadataStore.fetchAllSecretDataItems(
        encKey,
        authKeyPair,
      );
      const allItemIds = allItems.map((item) => item.itemId) as string[];

      const lockId = await metadataStore.acquireMetadataLock(authKeyPair);

      await expect(
        metadataStore.batchDeleteSecretDataItems(allItemIds, authKeyPair),
      ).rejects.toThrow('Cannot delete the PRIMARY_SRP item');

      await metadataStore.releaseMetadataLock(authKeyPair, lockId);
    });
  });
});
