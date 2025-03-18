import { keccak256 } from 'ethereum-cryptography/keccak';
import log from 'loglevel';

import { keccak256AndHexify, Some, SomeV1 } from './common';
import { waitFor } from './internal';

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

    const callbackFnFactory =
      (threshold: number) => async (resultArr: { data: string }[]) => {
        const completedResult = resultArr.filter((result) =>
          Boolean(result?.data),
        );
        if (completedResult.length >= threshold) {
          await waitFor(1_000);
          return completedResult.map((result) => result?.data || '');
        }
        throw new Error('not enough data');
      };

    it('`Some` and `SomeV1` should return the same result', async function () {
      const threshold = 2;
      const callbackFn = callbackFnFactory(threshold);

      let start = Date.now();
      const result = await SomeV1(promises, callbackFn);
      log.info('`SomeV1` execution time', Date.now() - start);

      start = Date.now();
      const genericResult = await Some(promises, callbackFn);
      log.info('`Some` execution time', Date.now() - start);

      expect(result).toStrictEqual(genericResult);
    });

    it('`Some` should throw an error when not enough promises are resolved', async function () {
      const threshold = 3;
      const callbackFn = callbackFnFactory(threshold);

      await expect(() => Some(promises, callbackFn)).rejects.toThrow(
        'not enough data',
      );
    });
  });
});
