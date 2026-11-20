import { sign } from 'jsonwebtoken';
import type { Algorithm as JwtAlgorithm } from 'jsonwebtoken';

/**
 * Gets the test JWT private key from the `TEST_JWT_PRIVATE_KEY` environment variable.
 *
 * Secret stores often flatten the PEM onto one line with escaped newlines, and
 * values pasted by hand may include quotes, so this normalizes those cases.
 *
 * @returns The test JWT private key in PEM format.
 */
function getJwtPrivateKey(): string {
  // eslint-disable-next-line n/no-process-env
  const raw = process.env.TEST_JWT_PRIVATE_KEY;
  if (!raw) {
    throw new Error(
      'TEST_JWT_PRIVATE_KEY environment variable is required to generate test ID tokens',
    );
  }

  const key = raw
    .trim()
    .replace(/^["']|["']$/gu, '')
    .trim()
    .replace(/\\n/gu, '\n');
  return key.includes('-----BEGIN')
    ? key
    : `-----BEGIN PRIVATE KEY-----\n${key}\n-----END PRIVATE KEY-----`;
}

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

  return sign(payload, getJwtPrivateKey(), algo);
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
  return `${Math.random().toString(36).slice(2, 10)}@example.com`;
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
export const generateMetadataAccessToken = (
  userId: string,
): (() => Promise<{ metadataAccessToken: string }>) => {
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
