import { sign } from 'jsonwebtoken';
import type { Algorithm as JwtAlgorithm } from 'jsonwebtoken';

const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;

// TODO: Replace with the dynamic values
// Test Private key to be used for generating the auth token
// Test audience to be used for generating the auth token

/**
 * Generates the id token for the given user id and algorithm.
 *
 * @param userId - The user id of the user.
 * @param alg - The algorithm.
 * @param aud - The audience.
 * @returns The id token.
 */
export const generateIdToken = (
  userId: string,
  alg: JwtAlgorithm,
  aud = 'torus-key-test',
): string => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'torus-key-test',
    aud,
    name: userId,
    email: userId,
    scope: 'email',
    iat,
    eat: iat + 120,
    env: 'testcases',
  };

  const algo = {
    expiresIn: 120,
    algorithm: alg,
  };

  return sign(payload, jwtPrivateKey, algo);
};

/**
 * Generates a random password for testing purposes.
 *
 * @returns A random password.
 */
export function generateRandomPassword(): string {
  const length = Math.random() * 10 + 8;
  return Math.random().toString(36).slice(2, length);
}

/**
 * Generates a random user id for testing purposes.
 *
 * @returns A random user id.
 */
export function generateRandomUserId(): string {
  return Math.random().toString(36).slice(2, 10);
}

/**
 * Pauses execution for the specified number of milliseconds.
 *
 * @param ms - The number of milliseconds to sleep.
 * @returns A promise that resolves after the specified time.
 */
export const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Generates the metadata access token for the given user id.
 *
 * @param userId - The user id of the user.
 * @returns a function that can be used to fetch the metadata access token.
 */
export const generateMetadataAccessToken = (userId: string) => {
  /**
   * Mock function to fetch metadata access credentials.
   *
   * @returns The metadata access credentials.
   */
  const fetchMetadataAccessCreds = async (): Promise<{
    metadataAccessToken: string;
  }> => ({
    metadataAccessToken: generateIdToken(
      userId,
      'ES256',
      'sapphire_devnet/w3a-metadata',
    ),
  });

  return fetchMetadataAccessCreds;
};
