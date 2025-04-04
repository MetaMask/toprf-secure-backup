import type { JRPCResponse } from "@toruslabs/constants";
/**
 * Hashes a buffer using the keccak256 algorithm and hexify the result
 *
 * @param buffer - The uint8array to hash
 * @returns The hash of the buffer as a hex string
 */
export declare function keccak256AndHexify(buffer: Uint8Array): `0x${string}`;
/**
 * Stringifies a JSON object and persists the key orders of the object
 *
 * @param json - The JSON object to stringify
 * @returns The stringified JSON object
 */
export declare function safeStringify(json: unknown): string;
/**
 * Finds the first element that appears t times in the array
 *
 * @param arr - The array to search
 * @param t - The number of times the element should appear
 * @returns The first element that appears t times in the array
 */
export declare function thresholdSame<T>(arr: T[], t: number): T | undefined;
/**
 *
 * @param s - The set to generate combinations from
 * @param k - The number of elements in each combination
 * @returns All possible combinations of k elements from the set s
 */
export declare function kCombinations(s: number | number[], k: number): number[][];
/**
 *
 * @param indexes - The indexes to choose from.
 * @param verifier - The verifier to use to generate the index
 * @param verifierId - The verifier id to use to generate the index
 * @returns The node index of the proxy coordinator endpoint.
 */
export declare const getProxyCoordinatorNodeIndex: (indexes: number[], verifier: string, verifierId: string) => number;
/**
 *
 * @param arr - The array to calculate the median of
 * @returns The median of the array
 */
export declare function calculateMedian(arr: number[]): number;
/**
 *
 * @param executionPromise - The promise to retry
 * @param maxRetries - The maximum number of retries
 * @returns The result of the promise
 */
export declare function retryPromiseWithBackoff<T>(executionPromise: () => Promise<JRPCResponse<T>>, maxRetries: number): Promise<JRPCResponse<T>>;
/**
 * This function executes an array of promises and returns a result of the operation based on the callbackFn return value
 *
 * @param promises - array of promises to execute
 * @param callbackFn - function to execute resolved promises and determine the outcome of the operation conditionally
 * @returns - result of the operation
 */
export declare function Some<K, T>(promises: Promise<K>[], callbackFn: (resultArr: K[], params?: {
    resolved: boolean;
}) => Promise<T>): Promise<T | void>;
export type Primitive = string | number | boolean | null;
export type JSONObject = {
    [key: string]: JSONValue;
};
export type JSONArray = JSONValue[];
export type JSONValue = Primitive | JSONObject | JSONArray;
/**
 *
 * @param str - The string to convert to camelCase.
 * @returns The camelCase string.
 */
export declare function toCamel(str: string): string;
/**
 *
 * @param str - The string to convert to snake_case.
 * @returns The snake_case string.
 */
export declare function toSnake(str: string): string;
/**
 *
 * @param obj - The object to convert the keys of.
 * @param convertFunc - The function to convert the keys of the object.
 * @returns The object with the converted keys.
 */
export declare function convertKeys(obj: JSONValue, convertFunc: (key: string) => string): JSONValue;
/**
 * Converts the keys of an object from snake_case to camelCase.
 *
 * @param obj - The object to convert the keys of.
 * @returns The object with the converted keys.
 */
export declare const toCamelCaseKeys: (obj: JSONValue) => JSONValue;
/**
 * Converts the keys of an object from camelCase to snake_case.
 *
 * @param obj - The object to convert the keys of.
 * @returns The object with the converted keys.
 */
export declare const toSnakeCaseKeys: (obj: JSONValue) => JSONValue;
//# sourceMappingURL=common.d.mts.map