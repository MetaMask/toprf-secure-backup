import { keccak_256 as keccak256 } from '@noble/hashes/sha3';

import type { JSONValue } from './common';
import {
  filterCompletedRequests,
  filterErrorResponses,
  getProxyCoordinatorNodeIndex,
  isJSONRPCError,
  kCombinations,
  keccak256AndHexify,
  safeStringify,
  Some,
  thresholdSame,
  toCamel,
  toCamelCaseKeys,
  toSnake,
  toSnakeCaseKeys,
  convertKeys,
  remove0x,
  add0x,
} from './common';
import { SomeError } from './errors';
import { waitFor } from './helpers';
import type { JSONRPCError } from './interfaces';

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

  describe('remove0x', () => {
    it('should remove the 0x prefix from a hex string', () => {
      expect(remove0x('0x1234567890')).toBe('1234567890');
    });

    it('should return the hex string if it does not start with 0x', () => {
      // @ts-expect-error - we are testing the type of the function
      expect(remove0x('1234567890')).toBe('1234567890');
    });
  });

  describe('add0x', () => {
    it('should add the 0x prefix to a hex string', () => {
      expect(add0x('1234567890')).toBe('0x1234567890');
    });

    it('should return the hex string if it already starts with 0x', () => {
      expect(add0x('0x1234567890')).toBe('0x1234567890');
    });
  });

  describe('safeStringify', () => {
    it('should stringify a simple object', () => {
      const obj = { b: 2, a: 1 };
      expect(safeStringify(obj)).toBe('{"a":1,"b":2}'); // Keys should be sorted
    });

    it('should stringify an object with nested properties', () => {
      const obj = { c: 3, a: 1, b: { y: 2, x: 1 } };
      expect(safeStringify(obj)).toBe('{"a":1,"b":{"x":1,"y":2},"c":3}');
    });

    it('should not throw an error for a boolean input', () => {
      expect(safeStringify(false)).toBe('false');
      expect(safeStringify(true)).toBe('true');
    });

    it('should not throw an error for date input', () => {
      const date = new Date();
      expect(safeStringify(date)).toBe(`"${date.toISOString()}"`);
    });

    it('should not throw an error for null input', () => {
      expect(safeStringify(null)).toBe('null');
    });

    it('should throw an error for circular references', () => {
      const obj: any = { a: 1 };
      obj.b = obj; // Circular reference
      expect(() => safeStringify(obj)).toThrow(
        'Converting circular structure to JSON',
      );
    });

    it('should throw an error for undefined input', () => {
      expect(() => safeStringify(undefined)).toThrow('Failed to stringify');
    });

    it('should throw an error for bigint input', () => {
      expect(() => safeStringify(BigInt(123))).toThrow(
        'Do not know how to serialize a BigInt',
      );
    });

    it('should throw an error for symbol input', () => {
      expect(() => safeStringify(Symbol('test'))).toThrow(
        'Failed to stringify',
      );
    });

    it('should throw an error for function input', () => {
      expect(() =>
        safeStringify(() => {
          return undefined;
        }),
      ).toThrow('Failed to stringify');
    });
  });

  describe('thresholdSame', () => {
    it('should return the item that appears threshold times', () => {
      const arr = ['a', 'b', 'b', 'c', 'c', 'c', 'd', 'd', 'd', 'd'];
      expect(thresholdSame(arr, 3)).toBe('c');
      expect(thresholdSame(arr, 4)).toBe('d');
      expect(thresholdSame(arr, 2)).toBe('b');
    });

    it('should return undefined if no item appears threshold times', () => {
      const arr = ['a', 'b', 'b', 'c', 'c', 'c', 'd', 'd', 'd', 'd'];
      expect(thresholdSame(arr, 5)).toBeUndefined();
    });

    it('should work with objects', () => {
      const obj1 = { a: 1 };
      const obj2 = { b: 2 };
      const obj3 = { a: 1 }; // Same as obj1
      const arr = [obj1, obj2, obj3];
      expect(thresholdSame(arr, 2)).toStrictEqual(obj1);
    });

    it('should handle empty array', () => {
      expect(thresholdSame([], 1)).toBeUndefined();
    });

    it('should handle threshold of 1', () => {
      expect(thresholdSame([5, 6, 7], 1)).toBe(5);
    });

    it('should skip items that cannot be stringified', () => {
      const arr = [1, 2, undefined, undefined, 2, 3, 3, 3];
      expect(thresholdSame(arr, 1)).toBe(1);
      expect(thresholdSame(arr, 2)).toBe(2);
      expect(thresholdSame(arr, 3)).toBe(3);
    });
  });

  describe('kCombinations', () => {
    it('should generate combinations for a set of numbers', () => {
      const set = [1, 2, 3, 4];
      const k = 2;
      const expectedCombinations = [
        [1, 2],
        [1, 3],
        [1, 4],
        [2, 3],
        [2, 4],
        [3, 4],
      ];
      const combinations = Array.from(kCombinations(set, k));
      expect(combinations).toStrictEqual(expectedCombinations);
    });

    it('should generate combinations when input is a number', () => {
      const set = 4; // Represents set [0, 1, 2, 3]
      const k = 3;
      const expectedCombinations = [
        [0, 1, 2],
        [0, 1, 3],
        [0, 2, 3],
        [1, 2, 3],
      ];
      const combinations = Array.from(kCombinations(set, k));
      expect(combinations).toStrictEqual(expectedCombinations);
    });

    it('should return empty generator if k > set length', () => {
      const set = [1, 2];
      const k = 3;
      const combinations = Array.from(kCombinations(set, k));
      expect(combinations).toStrictEqual([]);
    });

    it('should return empty generator if k <= 0', () => {
      const set = [1, 2, 3];
      expect(Array.from(kCombinations(set, 0))).toStrictEqual([]);
      expect(Array.from(kCombinations(set, -1))).toStrictEqual([]);
    });

    it('should return the set itself if k equals set length', () => {
      const set = [1, 2, 3];
      const k = 3;
      const combinations = Array.from(kCombinations(set, k));
      expect(combinations).toStrictEqual([set]);
    });

    it('should return combinations of single elements if k = 1', () => {
      const set = [1, 2, 3];
      const k = 1;
      const expectedCombinations = [[1], [2], [3]];
      const combinations = Array.from(kCombinations(set, k));
      expect(combinations).toStrictEqual(expectedCombinations);
    });
  });

  describe('getProxyCoordinatorNodeIndex', () => {
    it('should return a deterministic index within the bounds', () => {
      const indexes = [1, 2, 3, 4, 5];
      const authConnectionId = 'google';
      const userId = 'test@example.com';

      const index1 = getProxyCoordinatorNodeIndex(
        indexes,
        authConnectionId,
        userId,
      );
      expect(indexes).toContain(index1);

      const index2 = getProxyCoordinatorNodeIndex(
        indexes,
        authConnectionId,
        userId,
      );
      expect(index2).toBe(index1);

      const index3 = getProxyCoordinatorNodeIndex(
        indexes,
        'facebook',
        'another.user',
      );
      expect(indexes).toContain(index3);
    });

    it('should handle single element index array', () => {
      const indexes = [10];
      const authConnectionId = 'google';
      const userId = 'test@example.com';
      const index = getProxyCoordinatorNodeIndex(
        indexes,
        authConnectionId,
        userId,
      );
      expect(index).toBe(10);
    });
  });

  describe('`Some` function', function () {
    const promises: Promise<{ id: string; data: string }>[] = [
      new Promise((resolve) => {
        setTimeout(() => {
          resolve({ id: '1', data: 'success1' });
        }, 1_000);
      }),
      new Promise((_resolve, reject) => {
        setTimeout(() => {
          reject(new Error('test error'));
        }, 1_000);
      }),
      new Promise((resolve) => {
        setTimeout(() => {
          resolve({ id: '3', data: 'success3' });
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

    it('`Some` should resolve when enough promises are resolved', async function () {
      const threshold = 2;
      const callbackFn = callbackFnFactory(threshold);

      const result = await Some(promises, callbackFn);
      expect(result).toStrictEqual(['success1', 'success3']);
    });

    it('`Some` should throw SomeError when promises fail', async function () {
      const promisesFail: Promise<{ data: string }>[] = [
        Promise.reject(new Error('err1')),
        Promise.reject(new Error('err2')),
      ];

      const threshold = 2;
      const callbackFn = callbackFnFactory(threshold);
      await expect(Some(promisesFail, callbackFn)).rejects.toThrow(SomeError);
    });

    it('`Some` should throw SomeError via handleSomeCallBackFnError when callback condition is never met', async () => {
      const promisesAllSucceed: Promise<string>[] = [
        Promise.resolve('ok1'),
        Promise.resolve('ok2'),
      ];

      await expect(Some(promisesAllSucceed, async () => null)).rejects.toThrow(
        SomeError,
      );
    });

    it('`Some` should throw SomeError when promises succeed but do not satisfy predicate', async function () {
      const promisesSucceed: Promise<string>[] = [
        Promise.resolve('ok1'),
        Promise.resolve('ok2'),
      ];

      await expect(
        Some(promisesSucceed, () => {
          throw new Error('callback error');
        }),
      ).rejects.toThrow(SomeError);
    });

    it('`Some` should trigger SomeError when promises resolve with errors with data', async () => {
      const promisesWithErrorData: Promise<{ error: { data: string } }>[] = [
        Promise.resolve({ error: { data: 'error data 1' } }),
        Promise.resolve({ error: { data: 'error data 2' } }),
      ];

      await expect(
        Some(promisesWithErrorData, async () => null),
      ).rejects.toThrow(SomeError);
    });

    it('`Some` should trigger SomeError when promises resolve with errors with no data', async () => {
      const promisesWithError: Promise<{ error: string }>[] = [
        Promise.resolve({ error: 'error 1' }),
        Promise.resolve({ error: 'error 2' }),
      ];

      await expect(Some(promisesWithError, async () => null)).rejects.toThrow(
        SomeError,
      );
    });

    it('`Some` should throw an error when a promise times out', async () => {
      jest.useFakeTimers();

      const somePromise = Some(
        [
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({ id: '1', data: 'success1' });
            }, 12_000);
          }),
        ],
        async () => undefined,
      );

      jest.advanceTimersByTime(11_000);

      await expect(somePromise).rejects.toThrow('Promise timed out');

      jest.useRealTimers();
    });
  });

  describe('filterCompletedRequests', () => {
    it('should filter out undefined, null, and non-objects', () => {
      const input = [undefined, null, { result: 'ok' }, 'string', 5];
      const expected = [{ result: 'ok' }];
      expect(filterCompletedRequests(input)).toStrictEqual(expected);
    });

    it('should filter out objects with errors', () => {
      const input = [
        { result: 'ok' },
        { error: 'fail' },
        { result: 'ok2', error: null },
      ];
      const expected = [{ result: 'ok' }, { result: 'ok2', error: null }]; // error: null is considered no error
      expect(filterCompletedRequests(input)).toStrictEqual(expected);
    });

    it('should filter out objects without results', () => {
      const input = [{ result: 'ok' }, {}, { data: 'something' }];
      const expected = [{ result: 'ok' }];
      expect(filterCompletedRequests(input)).toStrictEqual(expected);
    });

    it('should handle empty array', () => {
      expect(filterCompletedRequests([])).toStrictEqual([]);
    });
  });

  describe('filterErrorResponses', () => {
    it('should filter out undefined, null, and non-objects', () => {
      const input = [undefined, null, { error: 'fail' }, 'string', 5];
      const expected = [{ error: 'fail' }];
      expect(filterErrorResponses(input)).toStrictEqual(expected);
    });

    it('should filter out objects without errors', () => {
      const input = [
        { result: 'ok' },
        { error: 'fail' },
        { result: 'ok2', error: null },
      ];
      const expected = [{ error: 'fail' }]; // error: null is considered no error
      expect(filterErrorResponses(input)).toStrictEqual(expected);
    });

    it('should handle empty array', () => {
      expect(filterErrorResponses([])).toStrictEqual([]);
    });
  });

  describe('isJSONRPCError', () => {
    it('should return true for valid JSONRPCError objects', () => {
      const validError: JSONRPCError = {
        code: -32000,
        message: 'Server error',
      };
      const validErrorWithData: JSONRPCError = {
        code: 123,
        message: 'Specific error',
        data: { details: 'more info' },
      };
      expect(isJSONRPCError(validError)).toBe(true);
      expect(isJSONRPCError(validErrorWithData)).toBe(true);
    });

    it('should return false for invalid objects or non-objects', () => {
      expect(isJSONRPCError(null)).toBe(false);
      expect(isJSONRPCError(undefined)).toBe(false);
      expect(isJSONRPCError('error string')).toBe(false);
      expect(isJSONRPCError(123)).toBe(false);
      expect(isJSONRPCError({})).toBe(false); // Missing code and message
      expect(isJSONRPCError({ code: 123 })).toBe(false); // Missing message
      expect(isJSONRPCError({ message: 'fail' })).toBe(false); // Missing code
      expect(isJSONRPCError({ code: '123', message: 'fail' })).toBe(false); // Invalid code type
      expect(isJSONRPCError({ code: 123, message: null })).toBe(false); // Invalid message type
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
          authConnectionId: 'test',
          userId: 'test',
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
          auth_connection_id: 'test',
          user_id: 'test',
        },
        verifier_oauth_params: {
          test: 'test',
        },
      },
      commitment_signatures: [],
      client_time: 'test',
    });
  });

  describe('convertKeys', () => {
    /**
     * Converts camelCase to SCREAMING_SNAKE_CASE
     *
     * @param str - The input string (camelCase)
     * @returns The output string (SCREAMING_SNAKE_CASE)
     */
    const screamingSnake = (str: string): string =>
      str.replace(/([A-Z])/gu, '_$1').toUpperCase();

    it('should convert keys using a provided function', () => {
      const obj = { myKey: 1, anotherKey: { nestedValue: true } };
      const expected = { MY_KEY: 1, ANOTHER_KEY: { NESTED_VALUE: true } };
      expect(convertKeys(obj, screamingSnake)).toStrictEqual(expected);
    });

    it('should handle arrays of objects', () => {
      const arr: JSONValue[] = [{ firstKey: 1 }, { secondKey: 2 }]; // Explicitly type as JSONValue[]
      const expected = [{ FIRST_KEY: 1 }, { SECOND_KEY: 2 }];
      expect(convertKeys(arr, screamingSnake)).toStrictEqual(expected);
    });

    it('should handle arrays of primitives', () => {
      const arr = [1, 'hello', true, null];
      expect(convertKeys(arr, screamingSnake)).toStrictEqual(arr);
      expect(convertKeys(123, screamingSnake)).toBe(123);
      expect(convertKeys(true, screamingSnake)).toBe(true);
      expect(convertKeys(null, screamingSnake)).toBeNull();
      expect(convertKeys(null, screamingSnake)).toBeNull();
    });

    it('should handle nested arrays', () => {
      const obj = { dataArray: [1, { nestedKey: 'value' }] };
      const expected = { DATA_ARRAY: [1, { NESTED_KEY: 'value' }] };
      expect(convertKeys(obj, screamingSnake)).toStrictEqual(expected);
    });

    it('should handle null values correctly', () => {
      const obj = { keyOne: null, keyTwo: { nestedNull: null } };
      const expected = { KEY_ONE: null, KEY_TWO: { NESTED_NULL: null } };
      expect(convertKeys(obj, screamingSnake)).toStrictEqual(expected);
    });

    it('should handle empty objects and arrays', () => {
      expect(convertKeys({}, screamingSnake)).toStrictEqual({});
      expect(convertKeys([], screamingSnake)).toStrictEqual([]);
      const obj = { emptyObj: {}, emptyArr: [] };
      const expected = { EMPTY_OBJ: {}, EMPTY_ARR: [] };
      expect(convertKeys(obj, screamingSnake)).toStrictEqual(expected);
    });

    it('should return primitives unchanged', () => {
      expect(convertKeys('string', screamingSnake)).toBe('string');
      expect(convertKeys(123, screamingSnake)).toBe(123);
      expect(convertKeys(true, screamingSnake)).toBe(true);
      expect(convertKeys(null, screamingSnake)).toBeNull();
    });
  });
});
