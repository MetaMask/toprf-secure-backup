import type {
  EciesHex,
  JRPCRequest,
  JSONValue,
} from '@metamask/auth-network-utils';
import {
  encParamsHexToBuf,
  toCamelCaseKeys,
  toSnakeCaseKeys,
} from '@metamask/auth-network-utils';
import { decrypt } from '@toruslabs/eccrypto';
import { post } from '@toruslabs/http-helpers';
import BN from 'bn.js';

type EncryptedData = {
  data: string;
  metadata: Omit<EciesHex, 'ciphertext'>;
};

/**
 * Converts a BigInt to BN
 *
 * @param value - BigInt value to convert
 * @returns BN instance
 */
export const bigIntToBN = (value: bigint): BN => {
  return new BN(value.toString());
};

/**
 * Common post function that handles snake_case conversion of request params
 * and camelCase conversion of response result.
 *
 * @param endpoint - The endpoint to make the request to
 * @param request - The request object to send. The params are converted to snake_case.
 *
 * @returns The response with camelCase converted result
 */
export const postJRPCRequest = async <
  Response extends {
    id: number;
    jsonrpc: '2.0';
    result?: JSONValue | undefined;
    error?: {
      code: number;
      message: string;
      data?: unknown;
    };
  },
>(
  endpoint: string,
  request: JRPCRequest<JSONValue>,
): Promise<Response> => {
  const req = { ...request };
  req.params = toSnakeCaseKeys(request.params);

  return post<Response>(endpoint, req, {}, { logTracingHeader: false })
    .then((res) => {
      if (res.result) {
        res.result = toCamelCaseKeys(res.result);
      }
      return res;
    })
    .catch((er: unknown) => {
      return {
        id: request.id,
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Internal error',
          data: er,
        },
      } as Response;
    });
};

/**
 * Decrypts the auth token using the session private key
 *
 * @param authToken - The auth token to be decrypted.
 * @param sessionPrivateKey - The session private key to be used for the decryption.
 *
 * @returns The decrypted auth token.
 */
export const decryptAuthToken = async (
  authToken: string,
  sessionPrivateKey: Uint8Array,
): Promise<string> => {
  const authTokenData = JSON.parse(authToken) as EncryptedData;
  const metadata = encParamsHexToBuf(authTokenData.metadata);

  const decryptedAuthToken = await decrypt(Buffer.from(sessionPrivateKey), {
    ...metadata,
    ciphertext: Buffer.from(authTokenData.data, 'hex'),
  });
  return Buffer.from(decryptedAuthToken).toString('base64');
};
