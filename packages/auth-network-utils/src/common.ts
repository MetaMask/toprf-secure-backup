import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import type { JRPCResponse } from '@toruslabs/constants';
import BN from 'bn.js';
import JsonStringify from 'json-stable-stringify';

import { SomeError } from './errors';
import { waitFor } from './helpers';

/**
 * Hashes a buffer using the keccak256 algorithm and hexify the result
 *
 * @param buffer - The uint8array to hash
 * @returns The hash of the buffer as a hex string
 */
export function keccak256AndHexify(buffer: Uint8Array): `0x${string}` {
  const hash = Buffer.from(keccak256(buffer)).toString('hex');
  return `0x${hash}`;
}

/**
 * Stringifies a JSON object and persists the key orders of the object
 *
 * @param json - The JSON object to stringify
 * @returns The stringified JSON object
 */
export function safeStringify(json: unknown): string {
  const stringified = JsonStringify(json);
  if (!stringified) {
    throw new Error('Failed to stringify');
  }
  return stringified;
}

/**
 * Finds the first element that appears t times in the array
 *
 * @param arr - The array to search
 * @param threshold - The number of times the element should appear
 * @returns The first element that appears t times in the array
 */
export function thresholdSame<Type>(
  arr: Type[],
  threshold: number,
): Type | undefined {
  const hashMap: Record<string, number> = {};
  for (const item of arr) {
    const str = JsonStringify(item);
    if (!str) {
      continue;
    }
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === threshold) {
      return item;
    }
  }
  return undefined;
}

/**
 * Generates all possible combinations of k elements from a set.
 *
 * @param inputSet - The set to generate combinations from
 * @param k - The number of elements in each combination
 * @returns All possible combinations of k elements from the set s
 */
export function kCombinations(
  inputSet: number | number[],
  k: number,
): number[][] {
  let set = inputSet;
  if (typeof set === 'number') {
    set = Array.from({ length: set }, (_, i) => i);
  }
  if (k > set.length || k <= 0) {
    return [];
  }

  if (k === set.length) {
    return [set];
  }

  if (k === 1) {
    return set.reduce<number[][]>((acc, cur) => [...acc, [cur]], []);
  }

  const combs: number[][] = [];
  let tailCombs: number[][] = [];

  const indices = Array.from({ length: set.length - k + 2 }, (_, i) => i);
  for (const i of indices) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1);
    for (const j of tailCombs) {
      combs.push([set[i], ...j]);
    }
  }

  return combs;
}

/**
 * Calculates the index of the proxy coordinator endpoint based on verifier details
 *
 * @param indexes - The indexes to choose from.
 * @param verifier - The verifier to use to generate the index
 * @param verifierId - The verifier id to use to generate the index
 * @returns The node index of the proxy coordinator endpoint.
 */
export const getProxyCoordinatorNodeIndex = (
  indexes: number[],
  verifier: string,
  verifierId: string,
): number => {
  const verifierIdStr = `${verifier}${verifierId}`;
  const hashedVerifierId = keccak256AndHexify(
    Buffer.from(verifierIdStr, 'utf8'),
  ).slice(2);
  const proxyEndpointNum = new BN(hashedVerifierId, 'hex')
    .mod(new BN(indexes.length))
    .toNumber();
  return indexes[proxyEndpointNum];
};

/**
 *
 * @param arr - The array to calculate the median of
 * @returns The median of the array
 */
export function calculateMedian(arr: number[]): number {
  const arrSize = arr.length;

  if (arrSize === 0) {
    return 0;
  }
  const sortedArr = arr.sort(function (a, b) {
    return a - b;
  });

  // odd length
  if (arrSize % 2 !== 0) {
    return sortedArr[Math.floor(arrSize / 2)];
  }

  // return average of two mid values in case of even arrSize
  const mid1 = sortedArr[arrSize / 2 - 1];

  const mid2 = sortedArr[arrSize / 2];
  return (mid1 + mid2) / 2;
}

/**
 *
 * @param executionPromise - The promise to retry
 * @param maxRetries - The maximum number of retries
 * @returns The result of the promise
 */
export async function retryPromiseWithBackoff<Type>(
  executionPromise: () => Promise<JRPCResponse<Type>>,
  maxRetries: number,
): Promise<JRPCResponse<Type>> {
  // Notice that we declare an inner function here
  // so we can encapsulate the retries and don't expose
  // it to the caller. This is also a recursive function
  /**
   *
   * @param retries - The number of retries
   * @returns The result of the promise
   */
  async function retryWithBackoff(
    retries: number,
  ): Promise<JRPCResponse<Type>> {
    try {
      // we don't wait on the first attempt
      if (retries > 0) {
        // on every retry, we exponentially increase the time to wait.
        // Here is how it looks for a `maxRetries` = 4
        // (2 ** 1) * 100 = 200 ms
        // (2 ** 2) * 100 = 400 ms
        // (2 ** 3) * 100 = 800 ms
        const timeToWait = 2 ** retries * 100;
        await waitFor(timeToWait);
      }
      const a = await executionPromise();
      return a;
    } catch (error: unknown) {
      const errorMsg = (error as Error).message;
      const acceptedErrorMsgs = [
        // Slow node
        'Timed out',
        'Failed to fetch',
        'fetch failed',
        'Load failed',
        'cancelled',
        'NetworkError when attempting to fetch resource.',
        // Happens when the node is not reachable (dns issue etc)
        'TypeError: Failed to fetch', // All except iOS and Firefox
        'TypeError: cancelled', // iOS
        'TypeError: NetworkError when attempting to fetch resource.', // Firefox
      ];

      if (
        retries < maxRetries &&
        (acceptedErrorMsgs.includes(errorMsg) ||
          errorMsg?.includes('reason: getaddrinfo EAI_AGAIN'))
      ) {
        // only retry if we didn't reach the limit
        // otherwise, let the caller handle the error
        return retryWithBackoff(retries + 1);
      }
      throw error;
    }
  }

  return retryWithBackoff(0);
}

/**
 * This function handles when `Some` function cannot determine the outcome of the operation\
 * even after all promises are settled
 *
 * @param errorArr - array of errors
 * @param resultArr - array of resolved results
 * @param predicateError - error thrown by the callbackFn
 */
function handleSomeCallBackFnError<Type>(
  errorArr: Error[],
  resultArr: Type[],
  predicateError?: Error,
): void {
  // check if there's any rejected promises
  let hasError = errorArr.some((error) => error !== undefined);
  if (hasError) {
    throw new SomeError({
      errors: errorArr,
      responses: resultArr,
      predicate: (predicateError as Error)?.message || 'unknown error',
    });
  }

  // check if there're any error inside resolved result array
  hasError = resultArr.some((result) => Boolean(result));
  if (hasError) {
    const errors = resultArr.map((result) => {
      const { error } = result as { error?: { data?: string } };
      if (error?.data && error.data.length > 0) {
        return new Error(error.data);
      }
      return undefined;
    });
    throw new SomeError({
      errors,
      responses: resultArr,
      predicate: (predicateError as Error)?.message || 'unknown error',
    });
  }

  // throw an `unkown` error if there's no error or resolved result
  throw new SomeError({
    errors: errorArr,
    responses: resultArr,
    predicate: (predicateError as Error)?.message || 'unknown error',
  });
}

/**
 * This function executes an array of promises and returns a result of the operation based on the callbackFn return value
 *
 * @param promises - array of promises to execute
 * @param callbackFn - function to execute resolved promises and determine the outcome of the operation conditionally
 * @returns - result of the operation
 */
export async function Some<Input, Output>(
  promises: Promise<Input>[],
  callbackFn: (
    resultArr: Input[],
    params?: { resolved: boolean },
  ) => Promise<Output>,
): Promise<Output> {
  let predicateError: Error | undefined; // to keep track of the latest error thrown by the callbackFn
  const resultArr: Input[] = new Array(promises.length).fill(undefined);
  const errorArr: Error[] = new Array(promises.length).fill(undefined);

  for (const [i, promise] of promises.entries()) {
    try {
      resultArr[i] = await promise;
    } catch (error: unknown) {
      errorArr[i] = error as Error;
    }

    try {
      const result = await callbackFn(resultArr);
      if (result) {
        return result;
      }
    } catch (error: unknown) {
      predicateError = error as Error;
    }
  }

  // If we still don't have a result, handle the error
  handleSomeCallBackFnError(errorArr, resultArr, predicateError);
  // If handleSomeCallBackFnError doesn't throw, throw a generic error
  throw new Error('Some function failed to produce a valid result');
}

/**
 * Filters out invalid responses.
 *
 * @param resultArr - The result array to filter.
 * @returns The filtered result array.
 */
export function filterCompletedRequests<Type>(resultArr: Type[]): Type[] {
  return resultArr.filter((res) => {
    if (!res || typeof res !== 'object') {
      return false;
    }
    if ('error' in res && res.error) {
      return false;
    }
    return true;
  });
}

export type Primitive = string | number | boolean | null;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = JSONValue[];
export type JSONValue = Primitive | JSONObject | JSONArray;

// Convert snake_case to camelCase
/**
 *
 * @param str - The string to convert to camelCase.
 * @returns The camelCase string.
 */
export function toCamel(str: string): string {
  return str.replace(/_([a-z])/gu, (_, letter) => letter.toUpperCase());
}

// Convert camelCase to snake_case
/**
 *
 * @param str - The string to convert to snake_case.
 * @returns The snake_case string.
 */
export function toSnake(str: string): string {
  return str.replace(/([A-Z])/gu, '_$1').toLowerCase();
}

// Recursive key converter
/**
 *
 * @param obj - The object to convert the keys of.
 * @param convertFunc - The function to convert the keys of the object.
 * @returns The object with the converted keys.
 */
export function convertKeys(
  obj: JSONValue,
  convertFunc: (key: string) => string,
): JSONValue {
  if (Array.isArray(obj)) {
    return obj.map((item) => convertKeys(item, convertFunc));
  } else if (obj !== null && typeof obj === 'object') {
    const newObj: JSONObject = {};
    for (const [key, value] of Object.entries(obj)) {
      newObj[convertFunc(key)] = convertKeys(value, convertFunc);
    }
    return newObj;
  }
  return obj;
}

/**
 * Converts the keys of an object from snake_case to camelCase.
 *
 * @param obj - The object to convert the keys of.
 * @returns The object with the converted keys.
 */
export const toCamelCaseKeys = (obj: JSONValue): JSONValue =>
  convertKeys(obj, toCamel);

/**
 * Converts the keys of an object from camelCase to snake_case.
 *
 * @param obj - The object to convert the keys of.
 * @returns The object with the converted keys.
 */
export const toSnakeCaseKeys = (obj: JSONValue): JSONValue =>
  convertKeys(obj, toSnake);
