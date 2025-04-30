import BN from 'bn.js';

import {
  generateEmptyBNArray,
  capitalizeFirstLetter,
  waitFor,
} from './helpers';

jest.useFakeTimers();

describe('helpers', () => {
  describe('generateEmptyBNArray', () => {
    it('should generate an array of the correct length', () => {
      const length = 5;
      const arr = generateEmptyBNArray(length);
      expect(arr).toHaveLength(length);
      arr.forEach((bn) => {
        expect(bn).toBeInstanceOf(BN);
        expect(bn.eqn(0)).toBe(true);
      });
    });

    it('should handle length 0', () => {
      expect(generateEmptyBNArray(0)).toStrictEqual([]);
    });
  });

  describe('capitalizeFirstLetter', () => {
    it('should capitalize the first letter of a lowercase string', () => {
      expect(capitalizeFirstLetter('hello')).toBe('Hello');
    });

    it('should return an already capitalized string unchanged', () => {
      expect(capitalizeFirstLetter('World')).toBe('World');
    });

    it('should handle single character strings', () => {
      expect(capitalizeFirstLetter('a')).toBe('A');
      expect(capitalizeFirstLetter('Z')).toBe('Z');
    });

    it('should handle empty string', () => {
      expect(capitalizeFirstLetter('')).toBe('');
    });

    it('should only capitalize the very first letter', () => {
      expect(capitalizeFirstLetter('hello world')).toBe('Hello world');
    });
  });

  describe('waitFor', () => {
    it('should resolve after the specified time', async () => {
      const waitTime = 500;
      const promise = waitFor(waitTime);

      jest.advanceTimersByTime(waitTime);

      expect(await promise).toBeUndefined();
    });

    it('should use the default timeout if none is provided', async () => {
      const defaultWaitTime = 2_000;
      const promise = waitFor(); // No argument provided

      jest.advanceTimersByTime(defaultWaitTime);

      expect(await promise).toBeUndefined();
    });

    it('should not resolve if the timeout is not reached', async () => {
      const waitTime = 500;
      const promise = waitFor(waitTime);

      jest.advanceTimersByTime(waitTime - 1);

      // The promise should still be pending since we haven't waited the full time
      const promiseStatus = await Promise.race([
        promise.then(() => 'resolved'),
        Promise.resolve('pending'),
      ]);
      expect(promiseStatus).toBe('pending');
    });
  });
});
