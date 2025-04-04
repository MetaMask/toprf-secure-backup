import BN from 'bn.js';

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
