"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.toSnakeCaseKeys = exports.toCamelCaseKeys = exports.convertKeys = exports.toSnake = exports.toCamel = exports.Some = exports.retryPromiseWithBackoff = exports.calculateMedian = exports.getProxyCoordinatorNodeIndex = exports.kCombinations = exports.thresholdSame = exports.safeStringify = exports.keccak256AndHexify = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
const keccak_1 = require("ethereum-cryptography/keccak");
const json_stable_stringify_1 = __importDefault(require("json-stable-stringify"));
const errors_1 = require("./errors.cjs");
const helpers_1 = require("./helpers.cjs");
/**
 * Hashes a buffer using the keccak256 algorithm and hexify the result
 *
 * @param buffer - The uint8array to hash
 * @returns The hash of the buffer as a hex string
 */
function keccak256AndHexify(buffer) {
    const hash = Buffer.from((0, keccak_1.keccak256)(buffer)).toString('hex');
    return `0x${hash}`;
}
exports.keccak256AndHexify = keccak256AndHexify;
/**
 * Stringifies a JSON object and persists the key orders of the object
 *
 * @param json - The JSON object to stringify
 * @returns The stringified JSON object
 */
function safeStringify(json) {
    const stringified = (0, json_stable_stringify_1.default)(json);
    if (!stringified) {
        throw new Error('Failed to stringify');
    }
    return stringified;
}
exports.safeStringify = safeStringify;
/**
 * Finds the first element that appears t times in the array
 *
 * @param arr - The array to search
 * @param t - The number of times the element should appear
 * @returns The first element that appears t times in the array
 */
function thresholdSame(arr, t) {
    const hashMap = {};
    for (const item of arr) {
        const str = (0, json_stable_stringify_1.default)(item);
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
exports.thresholdSame = thresholdSame;
/**
 *
 * @param s - The set to generate combinations from
 * @param k - The number of elements in each combination
 * @returns All possible combinations of k elements from the set s
 */
function kCombinations(s, k) {
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
        return set.reduce((acc, cur) => [...acc, [cur]], []);
    }
    const combs = [];
    let tailCombs = [];
    const indices = Array.from({ length: set.length - k + 2 }, (_, i) => i);
    for (const i of indices) {
        tailCombs = kCombinations(set.slice(i + 1), k - 1);
        for (const j of tailCombs) {
            combs.push([set[i], ...j]);
        }
    }
    return combs;
}
exports.kCombinations = kCombinations;
/**
 *
 * @param indexes - The indexes to choose from.
 * @param verifier - The verifier to use to generate the index
 * @param verifierId - The verifier id to use to generate the index
 * @returns The node index of the proxy coordinator endpoint.
 */
const getProxyCoordinatorNodeIndex = (indexes, verifier, verifierId) => {
    const verifierIdStr = `${verifier}${verifierId}`;
    const hashedVerifierId = keccak256AndHexify(Buffer.from(verifierIdStr, 'utf8')).slice(2);
    const proxyEndpointNum = new bn_js_1.default(hashedVerifierId, 'hex')
        .mod(new bn_js_1.default(indexes.length))
        .toNumber();
    return indexes[proxyEndpointNum];
};
exports.getProxyCoordinatorNodeIndex = getProxyCoordinatorNodeIndex;
/**
 *
 * @param arr - The array to calculate the median of
 * @returns The median of the array
 */
function calculateMedian(arr) {
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
exports.calculateMedian = calculateMedian;
/**
 *
 * @param executionPromise - The promise to retry
 * @param maxRetries - The maximum number of retries
 * @returns The result of the promise
 */
async function retryPromiseWithBackoff(executionPromise, maxRetries) {
    // Notice that we declare an inner function here
    // so we can encapsulate the retries and don't expose
    // it to the caller. This is also a recursive function
    /**
     *
     * @param retries - The number of retries
     * @returns The result of the promise
     */
    async function retryWithBackoff(retries) {
        try {
            // we don't wait on the first attempt
            if (retries > 0) {
                // on every retry, we exponentially increase the time to wait.
                // Here is how it looks for a `maxRetries` = 4
                // (2 ** 1) * 100 = 200 ms
                // (2 ** 2) * 100 = 400 ms
                // (2 ** 3) * 100 = 800 ms
                const timeToWait = 2 ** retries * 100;
                await (0, helpers_1.waitFor)(timeToWait);
            }
            const a = await executionPromise();
            return a;
        }
        catch (e) {
            const errorMsg = e.message;
            const acceptedErrorMsgs = [
                // Slow node
                'Timed out',
                'Failed to fetch',
                'fetch failed',
                'Load failed',
                'cancelled',
                'NetworkError when attempting to fetch resource.',
                // Happens when the node is not reachable (dns issue etc)
                'TypeError: Failed to fetch',
                'TypeError: cancelled',
                'TypeError: NetworkError when attempting to fetch resource.', // Firefox
            ];
            if (retries < maxRetries &&
                (acceptedErrorMsgs.includes(errorMsg) ||
                    (errorMsg && errorMsg.includes('reason: getaddrinfo EAI_AGAIN')))) {
                // only retry if we didn't reach the limit
                // otherwise, let the caller handle the error
                return retryWithBackoff(retries + 1);
            }
            throw e;
        }
    }
    return retryWithBackoff(0);
}
exports.retryPromiseWithBackoff = retryPromiseWithBackoff;
/**
 * This function handles when `Some` function cannot determine the outcome of the operation\
 * even after all promises are settled
 *
 * @param errorArr - array of errors
 * @param resultArr - array of resolved results
 * @param predicateError - error thrown by the callbackFn
 */
function handleSomeCallBackFnError(errorArr, resultArr, predicateError) {
    // check if there's any rejected promises
    let hasError = errorArr.some((error) => error !== undefined);
    if (hasError) {
        throw new errors_1.SomeError({
            errors: errorArr,
            responses: resultArr,
            predicate: predicateError?.message || 'unknown error',
        });
    }
    // check if there're any error inside resolved result array
    hasError = resultArr.some((result) => Boolean(result));
    if (hasError) {
        const errors = resultArr.map((result) => {
            const { error } = result;
            if (error?.data && error.data.length > 0) {
                return new Error(error.data);
            }
            return undefined;
        });
        throw new errors_1.SomeError({
            errors,
            responses: resultArr,
            predicate: predicateError?.message || 'unknown error',
        });
    }
    // throw an `unkown` error if there's no error or resolved result
    throw new errors_1.SomeError({
        errors: errorArr,
        responses: resultArr,
        predicate: predicateError?.message || 'unknown error',
    });
}
/**
 * This function executes an array of promises and returns a result of the operation based on the callbackFn return value
 *
 * @param promises - array of promises to execute
 * @param callbackFn - function to execute resolved promises and determine the outcome of the operation conditionally
 * @returns - result of the operation
 */
async function Some(promises, callbackFn) {
    let predicateError; // to keep track of the latest error thrown by the callbackFn
    let finishedCount = 0;
    const resultArr = new Array(promises.length).fill(undefined);
    const errorArr = new Array(promises.length).fill(undefined);
    for (const [i, promise] of promises.entries()) {
        try {
            resultArr[i] = await promise;
        }
        catch (e) {
            errorArr[i] = e;
        }
        try {
            const result = await callbackFn(resultArr);
            if (result) {
                return result;
            }
        }
        catch (e) {
            predicateError = e;
        }
        finally {
            finishedCount += 1;
        }
    }
    if (finishedCount === promises.length) {
        // handle error if the output of the callbackFn cannot be determined
        // after all promises are settled
        handleSomeCallBackFnError(errorArr, resultArr, predicateError);
    }
}
exports.Some = Some;
// Convert snake_case to camelCase
/**
 *
 * @param str - The string to convert to camelCase.
 * @returns The camelCase string.
 */
function toCamel(str) {
    return str.replace(/_([a-z])/gu, (_, letter) => letter.toUpperCase());
}
exports.toCamel = toCamel;
// Convert camelCase to snake_case
/**
 *
 * @param str - The string to convert to snake_case.
 * @returns The snake_case string.
 */
function toSnake(str) {
    return str.replace(/([A-Z])/gu, '_$1').toLowerCase();
}
exports.toSnake = toSnake;
// Recursive key converter
/**
 *
 * @param obj - The object to convert the keys of.
 * @param convertFunc - The function to convert the keys of the object.
 * @returns The object with the converted keys.
 */
function convertKeys(obj, convertFunc) {
    if (Array.isArray(obj)) {
        return obj.map((item) => convertKeys(item, convertFunc));
    }
    else if (obj !== null && typeof obj === 'object') {
        const newObj = {};
        for (const [key, value] of Object.entries(obj)) {
            newObj[convertFunc(key)] = convertKeys(value, convertFunc);
        }
        return newObj;
    }
    return obj;
}
exports.convertKeys = convertKeys;
/**
 * Converts the keys of an object from snake_case to camelCase.
 *
 * @param obj - The object to convert the keys of.
 * @returns The object with the converted keys.
 */
const toCamelCaseKeys = (obj) => convertKeys(obj, toCamel);
exports.toCamelCaseKeys = toCamelCaseKeys;
/**
 * Converts the keys of an object from camelCase to snake_case.
 *
 * @param obj - The object to convert the keys of.
 * @returns The object with the converted keys.
 */
const toSnakeCaseKeys = (obj) => convertKeys(obj, toSnake);
exports.toSnakeCaseKeys = toSnakeCaseKeys;
//# sourceMappingURL=common.cjs.map