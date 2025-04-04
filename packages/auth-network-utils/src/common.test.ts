import { utf8ToBytes } from '@noble/hashes/utils';
import { keccak256 } from 'ethereum-cryptography/keccak';

import {
  keccak256AndHexify,
  Some,
  thresholdReadSecretData,
  toCamel,
  toCamelCaseKeys,
  toSnake,
  toSnakeCaseKeys,
} from './common';
import { waitFor } from './helpers';

describe('common utils', function () {
  it('should be able to hash a buffer and hexify the result with `keccak256AndHexify', function () {
    const buffer = Buffer.from('test', 'utf8');

    const expectedHashedHexString = Buffer.from(keccak256(buffer)).toString(
      'hex',
    );

    const hexString = keccak256AndHexify(buffer);
    expect(hexString).toBe(
      '0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658',
    );
    expect(expectedHashedHexString).toStrictEqual(hexString.slice(2));
  });

  describe('`Some` function', function () {
    const promises: Promise<{ id: string; data: string }>[] = [
      new Promise((resolve) => {
        setTimeout(() => {
          resolve({ id: '1', data: 'test' });
        }, 1_000);
      }),
      new Promise((_resolve, reject) => {
        setTimeout(() => {
          reject(new Error('test error'));
        }, 1_000);
      }),
      new Promise((resolve) => {
        setTimeout(() => {
          resolve({ id: '3', data: 'test' });
        }, 1_000);
      }),
    ];

    /**
     *
     * @param threshold - The threshold for the number of promises to be resolved.
     *
     * @returns The callback function.
     */
    const callbackFnFactory =
      (threshold: number) =>
      async (resultArr: { data: string }[]): Promise<string[]> => {
        const completedResult = resultArr.filter((result) =>
          Boolean(result?.data),
        );
        if (completedResult.length >= threshold) {
          await waitFor(1_000);
          return completedResult.map((result) => result?.data || '');
        }
        throw new Error('not enough data');
      };

    it('`Some` should throw an error when not enough promises are resolved', async function () {
      const threshold = 3;
      const callbackFn = callbackFnFactory(threshold);

      await expect(async () => Some(promises, callbackFn)).rejects.toThrow(
        'not enough data',
      );
    });
  });

  it('should be able to convert a field to a camel case field', function () {
    const camelCaseObj = toCamel('auth_token');
    expect(camelCaseObj).toBe('authToken');
  });

  it('should be able to convert a field to a snake case field', function () {
    const snakeCaseObj = toSnake('authToken');
    expect(snakeCaseObj).toBe('auth_token');
  });

  it('should be able to convert keys to camel case', function () {
    const obj = {
      auth_token: 'test',
      node_index: 1,
      pub_key: 'test',
      key_index: 1,
    };

    const camelCaseObj = toCamelCaseKeys(obj);
    expect(camelCaseObj).toStrictEqual({
      authToken: 'test',
      nodeIndex: 1,
      pubKey: 'test',
      keyIndex: 1,
    });
  });

  it('should be able to convert keys to snake case', function () {
    const obj = {
      authData: {
        authenticationContext: {
          idToken: 'test',
          verifier: 'test',
          verifierId: 'test',
        },
        verifierOauthParams: {
          test: 'test',
        },
      },
      commitmentSignatures: [],
      clientTime: 'test',
    };

    const snakeCaseObj = toSnakeCaseKeys(obj);
    expect(snakeCaseObj).toStrictEqual({
      auth_data: {
        authentication_context: {
          id_token: 'test',
          verifier: 'test',
          verifier_id: 'test',
        },
        verifier_oauth_params: {
          test: 'test',
        },
      },
      commitment_signatures: [],
      client_time: 'test',
    });
  });
});

describe('thresholdReadSecretData', () => {
  /**
   * Creates a promise that resolves to an array of Uint8Arrays from strings
   *
   * @param data - Array of strings to be converted to Uint8Arrays
   * @returns Promise resolving to array of Uint8Arrays
   */
  const createPromise = async (data: string[]): Promise<Uint8Array[]> => {
    return Promise.resolve(data.map((str) => utf8ToBytes(str)));
  };

  it('should return data that meets threshold count', async () => {
    const commonData = ['1', '2', '3'];
    const promises = [
      createPromise(commonData),
      createPromise(commonData),
      createPromise(commonData),
    ];

    const result = await thresholdReadSecretData(promises, 3);
    expect(result).toHaveLength(3);
    expect(result.map((res) => Buffer.from(res).toString())).toStrictEqual(
      commonData,
    );
  });

  it('should return data that meets threshold when nodes have 2 versions of data', async () => {
    const commonData = ['1', '2', '3'];
    const extendedData = [...commonData, '4'];
    const promises = [
      createPromise(commonData),
      createPromise(extendedData),
      createPromise(extendedData),
      createPromise(commonData),
      createPromise(commonData),
    ];

    const result = await thresholdReadSecretData(promises, 3);
    expect(result).toHaveLength(3);
    expect(result.map((res) => Buffer.from(res).toString())).toStrictEqual(
      commonData,
    );
  });

  it('should return v1 data when v1 and v2 data is not available in threshold number of promises', async () => {
    const v1Data = ['1', '2', '3'];
    const v2Data = [...v1Data, '4'];
    const v3Data = [...v1Data, '5'];

    const promises = [
      createPromise(v1Data),
      createPromise(v1Data),
      createPromise(v2Data),
      createPromise(v2Data),
      createPromise(v3Data),
    ];

    const result = await thresholdReadSecretData(promises, 3);
    expect(result).toHaveLength(3);
    expect(result.map((res) => Buffer.from(res).toString())).toStrictEqual(
      v1Data,
    );
  });
});
