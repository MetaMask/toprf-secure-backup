import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import BN from 'bn.js';
import JsonStringify from 'json-stable-stringify';

import { SomeError } from './errors';
import type { JSONRPCError } from './interfaces';

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
 * @param options - The options to pass to the stringify function
 * @returns The stringified JSON object
 */
export function safeStringify(
  json: unknown,
  options?: Parameters<typeof JsonStringify>[1],
): string {
  const stringified = JsonStringify(json, options);
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
 * @yields All possible combinations of k elements from the set s
 */
export function* kCombinations(
  inputSet: number | number[],
  k: number,
): Generator<number[]> {
  let set = inputSet;
  if (typeof set === 'number') {
    set = Array.from({ length: set }, (_, i) => i);
  }
  if (k > set.length || k <= 0) {
    return;
  }

  if (k === set.length) {
    yield set;
    return;
  }

  if (k === 1) {
    for (const item of set) {
      yield [item];
    }
    return;
  }

  const indices = Array.from({ length: set.length - k + 2 }, (_, i) => i);
  for (const i of indices) {
    for (const j of kCombinations(set.slice(i + 1), k - 1)) {
      yield [set[i], ...j];
    }
  }
}

/**
 * Calculates the index of the proxy coordinator endpoint based on auth connection id details
 *
 * @param indexes - The indexes to choose from.
 * @param authConnectionId - The auth connection id to use to generate the index
 * @param userId - The user id to use to generate the index
 * @returns The node index of the proxy coordinator endpoint.
 */
export const getProxyCoordinatorNodeIndex = (
  indexes: number[],
  authConnectionId: string,
  userId: string,
): number => {
  const authConnectionIdStr = `${authConnectionId}${userId}`;
  const hashedAuthConnectionId = keccak256AndHexify(
    Buffer.from(authConnectionIdStr, 'utf8'),
  ).slice(2);
  const proxyEndpointNum = new BN(hashedAuthConnectionId, 'hex')
    .mod(new BN(indexes.length))
    .toNumber();
  return indexes[proxyEndpointNum];
};

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
): never {
  // check if there's any rejected promises
  let hasError = errorArr.some((error) => error !== undefined);
  if (hasError) {
    throw new SomeError({
      errors: errorArr,
      responses: resultArr,
      predicate: predicateError,
    });
  }

  type ResultWithError = { error?: { data?: string } };

  // check if there're any error inside resolved result array
  const resultArrWithError = resultArr as ResultWithError[];
  hasError = resultArrWithError.some((result) => Boolean(result?.error));
  if (hasError) {
    const errors = resultArr.map((result) => {
      const { error } = result as ResultWithError;
      if (error?.data && error.data.length > 0) {
        return new Error(error.data);
      }
      return undefined;
    });
    throw new SomeError({
      errors,
      responses: resultArr,
      predicate: predicateError,
    });
  }

  // no error was thrown and callback never returned a value
  throw new SomeError({
    errors: errorArr,
    responses: resultArr,
    predicate: predicateError,
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
    params: { allSettled: boolean },
  ) => Promise<Output | undefined>,
): Promise<Output> {
  let predicateError: Error | undefined; // to keep track of the latest error thrown by the callbackFn
  const resultArr: Input[] = new Array(promises.length).fill(undefined);
  const errorArr: Error[] = new Array(promises.length).fill(undefined);

  for (const [i, promise] of promises.entries()) {
    let timeoutId: NodeJS.Timeout | undefined;
    try {
      // Race the promise against a timeout
      const timeoutPromise = new Promise<Input>((_resolve, reject) => {
        timeoutId = setTimeout(
          () => reject(new Error('Promise timed out')),
          10_000,
        );
      });
      resultArr[i] = await Promise.race([promise, timeoutPromise]);
    } catch (error: unknown) {
      errorArr[i] = error as Error;
    } finally {
      // Clear the timeout if it exists and still hasn't been cleared after the Promise.race is settled.
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }

    try {
      const allSettled = resultArr.every((result) => result !== undefined);
      const result = await callbackFn(resultArr, { allSettled });
      if (result) {
        return result;
      }
    } catch (error: unknown) {
      predicateError = error as Error;
    }
  }

  // If we still don't have a result, handle the error
  handleSomeCallBackFnError(errorArr, resultArr, predicateError);
}

/**
 * Filters out invalid responses.
 *
 * @param resultArr - The result array to filter.
 * @returns The filtered result array.
 */
export function filterCompletedRequests<Type>(resultArr: Type[]): Type[] {
  return resultArr.filter((res) => {
    const isValidObject = res && typeof res === 'object';

    const maybeRes = res as { error?: unknown; result?: unknown };
    const hasNoError = !maybeRes?.error;
    const hasResult = Boolean(maybeRes?.result);

    return isValidObject && hasNoError && hasResult;
  });
}

/**
 * Extracts error responses from a result array.
 *
 * @param resultArr - Array of responses to check for errors
 * @returns Array of error responses extracted from the input array
 */
export function filterErrorResponses<Type>(
  resultArr: Type[],
): (Type & { error: unknown })[] {
  return resultArr.filter((res): res is Type & { error: unknown } => {
    const isValidObject = res && typeof res === 'object';

    const maybeRes = res as { error?: unknown };
    const hasError = Boolean(maybeRes?.error);

    return isValidObject && hasError;
  });
}

/**
 * Checks if an unknown value is a properly structured JSON-RPC error object
 *
 * @param error - The value to check
 * @returns True if the value is a JSON-RPC error object with the required properties
 */
export function isJSONRPCError(error: unknown): error is JSONRPCError {
  const isValidObject = Boolean(error && typeof error === 'object');

  const maybeError = error as Partial<JSONRPCError>;
  const hasCode = typeof maybeError?.code === 'number';
  const hasMessage = typeof maybeError?.message === 'string';

  return isValidObject && hasCode && hasMessage;
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
