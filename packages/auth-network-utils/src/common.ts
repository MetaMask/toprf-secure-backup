import type { JRPCResponse } from '@toruslabs/constants';
import BN from 'bn.js';
import { keccak256 } from 'ethereum-cryptography/keccak';
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
 * @param t - The number of times the element should appear
 * @returns The first element that appears t times in the array
 */
export function thresholdSame<T>(arr: T[], t: number): T | undefined {
  const hashMap: Record<string, number> = {};
  for (const item of arr) {
    const str = JsonStringify(item);
    if (!str) {
      continue;
    }
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === t) {
      return item;
    }
  }
  return undefined;
}

/**
 *
 * @param s - The set to generate combinations from
 * @param k - The number of elements in each combination
 * @returns All possible combinations of k elements from the set s
 */
export function kCombinations(s: number | number[], k: number): number[][] {
  let set = s;
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
 *
 * @param endpoints - The endpoints to choose from
 * @param verifier - The verifier to use to generate the index
 * @param verifierId - The verifier id to use to generate the index
 * @returns The index of the proxy coordinator endpoint
 */
export function getProxyCoordinatorEndpointIndex(
  endpoints: string[],
  verifier: string,
  verifierId: string,
) {
  const verifierIdStr = `${verifier}${verifierId}`;
  const hashedVerifierId = keccak256AndHexify(
    Buffer.from(verifierIdStr, 'utf8'),
  ).slice(2);
  const proxyEndpointNum = new BN(hashedVerifierId, 'hex')
    .mod(new BN(endpoints.length))
    .toNumber();
  return proxyEndpointNum;
}

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
export async function retryPromiseWithBackoff<T>(
  executionPromise: () => Promise<JRPCResponse<T>>,
  maxRetries: number,
) {
  // Notice that we declare an inner function here
  // so we can encapsulate the retries and don't expose
  // it to the caller. This is also a recursive function
  /**
   *
   * @param retries - The number of retries
   * @returns The result of the promise
   */
  async function retryWithBackoff(retries: number) {
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
    } catch (e: unknown) {
      const errorMsg = (e as Error).message;
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
          (errorMsg && errorMsg.includes('reason: getaddrinfo EAI_AGAIN')))
      ) {
        // only retry if we didn't reach the limit
        // otherwise, let the caller handle the error
        return retryWithBackoff(retries + 1);
      }
      throw e;
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
function handleSomeCallBackFnError<K>(
  errorArr: Error[],
  resultArr: K[],
  predicateError?: Error,
) {
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
export async function Some<K, T>(
  promises: Promise<K>[],
  callbackFn: (resultArr: K[], params?: { resolved: boolean }) => Promise<T>,
): Promise<T | void> {
  let predicateError: Error | undefined; // to keep track of the latest error thrown by the callbackFn

  const resultArr: K[] = new Array(promises.length).fill(undefined);
  const errorArr: Error[] = new Array(promises.length).fill(undefined);

  for (const [i, promise] of promises.entries()) {
    try {
      resultArr[i] = await promise;
    } catch (e: unknown) {
      errorArr[i] = e as Error;
    }

    try {
      const result = await callbackFn(resultArr);
      if (result) {
        return result;
      }
    } catch (e: unknown) {
      predicateError = e as Error;
    }
  }

  // handle error if the output of the callbackFn cannot be determined
  // after all promises are settled
  handleSomeCallBackFnError(errorArr, resultArr, predicateError);
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
