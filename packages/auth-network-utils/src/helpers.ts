import BN from 'bn.js';
import type { ec as EC } from 'elliptic';

/**
 * Generates an array of empty BN objects
 *
 * @param length - The length of the array
 * @returns The array of empty BN objects
 */
export function generateEmptyBNArray(length: number): BN[] {
  return Array.from({ length }, () => new BN(0));
}

/**
 * Capitalizes the first letter of a string
 *
 * @param str - The string to capitalize
 * @returns The string with the first letter capitalized
 */
export function capitalizeFirstLetter(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Waits for a specified number of milliseconds
 *
 * @param ms - The number of milliseconds to wait
 * @returns A promise that resolves after the specified number of milliseconds
 */
export async function waitFor(ms: number = 2_000): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Generates a random nonce
 *
 * @param curve - The elliptic curve to use
 * @returns The random nonce
 */
export function getRandomNonce(curve: EC): BN {
  const privateKey = curve.genKeyPair().getPrivate();
  const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
  return new BN(privateKeyBuffer);
}
