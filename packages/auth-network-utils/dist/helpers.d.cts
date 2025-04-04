import BN from "bn.js";
import type { ec as EC } from "elliptic";
/**
 * Generates an array of empty BN objects
 *
 * @param length - The length of the array
 * @returns The array of empty BN objects
 */
export declare function generateEmptyBNArray(length: number): BN[];
/**
 * Capitalizes the first letter of a string
 *
 * @param str - The string to capitalize
 * @returns The string with the first letter capitalized
 */
export declare function capitalizeFirstLetter(str: string): string;
/**
 * Waits for a specified number of milliseconds
 *
 * @param ms - The number of milliseconds to wait
 * @returns A promise that resolves after the specified number of milliseconds
 */
export declare function waitFor(ms?: number): Promise<void>;
/**
 * Generates a random nonce
 *
 * @param curve - The elliptic curve to use
 * @returns The random nonce
 */
export declare function getRandomNonce(curve: EC): BN;
//# sourceMappingURL=helpers.d.cts.map