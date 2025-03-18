import BN from 'bn.js';
import type { ec as EC } from 'elliptic';

/**
 *
 * @param length
 */
export function generateEmptyBNArray(length: number): BN[] {
  return Array.from({ length }, () => new BN(0));
}

/**
 *
 * @param str
 */
export function capitalizeFirstLetter(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 *
 * @param ms
 */
export async function waitFor(ms: number = 2_000): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 *
 * @param curve
 */
export function getRandomNonce(curve: EC): BN {
  const privateKey = curve.genKeyPair().getPrivate();
  const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
  return new BN(privateKeyBuffer);
}
