import type { JRPCResponse } from '@toruslabs/constants';
import type { Ecies } from '@toruslabs/eccrypto';
import BN from 'bn.js';
import type { ec as EC } from 'elliptic';
import { keccak256 } from 'ethereum-cryptography/keccak';
import JsonStringify from 'json-stable-stringify';

import { SomeError } from './errors';
import type {
  CommitmentRequestResult,
  EciesHex,
  GetORSetKeyResponse,
  VerifierLookupResponse,
} from './interfaces';
import { capitalizeFirstLetter, waitFor } from './internal';

// generate a 32 bytes private key buffer
/**
 *
 * @param ecCurve
 */
export function generate32BytesPrivateKeyBuffer(ecCurve: EC): Buffer {
  const privateKey = ecCurve.genKeyPair().getPrivate();
  const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
  return privateKeyBuffer;
}

/**
 * Hashes a buffer using the keccak256 algorithm and hexify the result
 *
 * @param buffer - The buffer to hash
 * @returns The hash of the buffer as a hex string
 */
export function keccak256AndHexify(buffer: Buffer): `0x${string}` {
  const hash = Buffer.from(keccak256(buffer)).toString('hex');
  return `0x${hash}`;
}

/**
 *
 * @param encParams
 */
export function encryptedParamsBufToHex(encParams: Ecies): EciesHex {
  return {
    iv: Buffer.from(encParams.iv).toString('hex'),
    ephemPublicKey: Buffer.from(encParams.ephemPublicKey).toString('hex'),
    ciphertext: Buffer.from(encParams.ciphertext).toString('hex'),
    mac: Buffer.from(encParams.mac).toString('hex'),
    mode: 'AES256',
  };
}

/**
 *
 * @param eciesData
 */
export function encParamsHexToBuf(
  eciesData: Omit<EciesHex, 'ciphertext'>,
): Omit<Ecies, 'ciphertext'> {
  return {
    ephemPublicKey: Buffer.from(eciesData.ephemPublicKey, 'hex'),
    iv: Buffer.from(eciesData.iv, 'hex'),
    mac: Buffer.from(eciesData.mac, 'hex'),
  };
}

// this function normalizes the result from nodes before passing the result to threshold check function
// For ex: some fields returns by nodes might be different from each other
// like created_at field might vary and nonce_data might not be returned by all nodes because
// of the metadata implementation in sapphire.
/**
 *
 * @param result
 */
export function normalizeKeysResult(result: GetORSetKeyResponse) {
  const finalResult: Pick<GetORSetKeyResponse, 'keys' | 'is_new_key'> = {
    keys: [],
    is_new_key: result.is_new_key,
  };
  if (result && result.keys && result.keys.length > 0) {
    const finalKey = result.keys[0];
    finalResult.keys = [
      {
        pub_key_X: finalKey.pub_key_X,
        pub_key_Y: finalKey.pub_key_Y,
        address: finalKey.address,
      },
    ];
  }
  return finalResult;
}

export const normalizeLookUpResult = (result: VerifierLookupResponse) => {
  const finalResult: Pick<VerifierLookupResponse, 'keys'> = {
    keys: [],
  };
  if (result && result.keys && result.keys.length > 0) {
    const finalKey = result.keys[0];
    finalResult.keys = [
      {
        pub_key_X: finalKey.pub_key_X,
        pub_key_Y: finalKey.pub_key_Y,
        address: finalKey.address,
      },
    ];
  }
  return finalResult;
};

/**
 *
 * @param arr
 * @param t
 */
export function thresholdSame<T>(arr: T[], t: number): T | undefined {
  const hashMap: Record<string, number> = {};
  for (let i = 0; i < arr.length; i += 1) {
    const str = JsonStringify(arr[i]);
    if (!str) {
      continue;
    }
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === t) {
      return arr[i];
    }
  }
  return undefined;
}

/**
 *
 * @param s
 * @param k
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
    return set.reduce((acc, cur) => [...acc, [cur]], [] as number[][]);
  }

  const combs: number[][] = [];
  let tailCombs: number[][] = [];

  for (let i = 0; i <= set.length - k + 1; i += 1) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1);
    for (let j = 0; j < tailCombs.length; j += 1) {
      combs.push([set[i], ...tailCombs[j]]);
    }
  }

  return combs;
}

/**
 *
 * @param endpoints
 * @param verifier
 * @param verifierId
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
 * @param arr
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
 * @param executionPromise
 * @param maxRetries
 */
export function retryCommitment(
  executionPromise: () => Promise<JRPCResponse<CommitmentRequestResult>>,
  maxRetries: number,
) {
  // Notice that we declare an inner function here
  // so we can encapsulate the retries and don't expose
  // it to the caller. This is also a recursive function
  /**
   *
   * @param retries
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

  for (let i = 0; i < promises.length; i += 1) {
    try {
      resultArr[i] = await promises[i];
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

/**
 * This function executes an array of promises and returns a result of the operation based on the predicate function return value.\
 * This function is the old implementation of `Some` and will be removed once the new implementation is fully tested and verified
 *
 * @deprecated Use `Some` instead
 *
 * @param promises - array of promises to execute
 * @param predicate - function to execute resolved promises and determine the outcome of the operation conditionally
 * @returns - result of the operation
 */
export function SomeV1<K, T>(
  promises: Promise<K>[],
  predicate: (
    resultArr: K[],
    { resolved }: { resolved: boolean },
  ) => Promise<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    let finishedCount = 0;
    const sharedState = { resolved: false };
    const errorArr: Error[] = new Array(promises.length).fill(undefined);
    const resultArr: K[] = new Array(promises.length).fill(undefined);
    let predicateError: Error | string;

    promises.forEach((x, index) => {
      // eslint-disable-next-line promise/catch-or-return
      x.then((resp: K): unknown => {
        resultArr[index] = resp;
        return undefined;
      })
        .catch((error: Error) => {
          errorArr[index] = error;
        })
        // eslint-disable-next-line promise/no-return-in-finally
        .finally(() => {
          if (sharedState.resolved) {
            return;
          }
          return predicate(resultArr.slice(0), sharedState)
            .then((data): unknown => {
              sharedState.resolved = true;
              resolve(data);
              return undefined;
            })
            .catch((error) => {
              // log only the last predicate error
              predicateError = error;
            })
            .finally(() => {
              finishedCount += 1;
              if (finishedCount === promises.length) {
                const errors = Object.values(
                  resultArr.reduce((acc: Record<string, string>, z) => {
                    if (z) {
                      const { id, error } = z as {
                        id?: string;
                        error?: { data?: string };
                      };
                      if (error?.data && error.data.length > 0 && id) {
                        if (
                          error.data.startsWith(
                            'Error occurred while verifying params',
                          )
                        ) {
                          acc[id] = capitalizeFirstLetter(error.data);
                        } else {
                          acc[id] = error.data;
                        }
                      }
                    }
                    return acc;
                  }, {}),
                );

                if (errors.length > 0) {
                  // Format-able errors
                  const msg =
                    errors.length > 1
                      ? `\n${errors.map((it) => `• ${it}`).join('\n')}`
                      : errors[0];
                  reject(new Error(msg));
                } else {
                  reject(
                    new SomeError({
                      errors: errorArr,
                      responses: resultArr,
                      predicate:
                        (predicateError as Error)?.message ||
                        (predicateError as string),
                    }),
                  );
                }
              }
            });
        });
    });
  });
}
