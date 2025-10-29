import type { JsonRpcVersion } from '@metamask/auth-network-utils';

import { JsonRpcErrorCodes } from './constants';
import { TOPRFError, TOPRFErrorCode } from './errors';
import { getPubKey, validatePubKey } from './getPubKeyRequest';
import type { GetPubKeyResult } from './jrpcInterfaces';

describe('getPubKey', () => {
  it('should fail with insufficient auth tokens', async function () {
    await expect(
      getPubKey({
        authTokens: [],
        nodeEndpointsMap: {},
        authConnectionId: 'torus-test-health',
        userId: 'dummy-id',
      }),
    ).rejects.toThrow(
      TOPRFError.insufficientAuthTokens(`At least 3 auth tokens are required.`),
    );
  });

  it('should fail on inconsistent pub key responses', async function () {
    const resultArr = ['1234', '1234', '5678', '5678'].map((pubKey) => ({
      id: 1,
      jsonrpc: '2.0' as JsonRpcVersion,
      result: { pubKey, keyIndex: 1 },
    }));

    await expect(validatePubKey(resultArr)).rejects.toThrow(
      TOPRFError.couldNotDeriveThresholdAuthPubKey(),
    );
  });
  it('should fail if key index is not present but pub key is present', async function () {
    const resultArr = ['1234', '1234', '1234', '1234'].map((pubKey) => ({
      id: 1,
      jsonrpc: '2.0' as JsonRpcVersion,
      result: { pubKey } as GetPubKeyResult,
    }));

    await expect(validatePubKey(resultArr)).rejects.toThrow(
      TOPRFError.couldNotDeriveThresholdAuthPubKey(),
    );
  });

  it('should throw auth token expired error when present in responses', async function () {
    const resultArr = [
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: { pubKey: '1234', keyIndex: 1 },
      },
      {
        id: 2,
        jsonrpc: '2.0' as JsonRpcVersion,
        error: {
          code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
          message: 'Auth token expired',
        },
      },
    ];

    await expect(validatePubKey(resultArr)).rejects.toMatchObject({
      code: TOPRFErrorCode.AuthTokenExpired,
    });
  });

  it('should throw invalid auth token error when present in responses', async function () {
    const resultArr = [
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: { pubKey: '1234', keyIndex: 1 },
      },
      {
        id: 2,
        jsonrpc: '2.0' as JsonRpcVersion,
        error: {
          code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
          message: 'Invalid auth token',
        },
      },
    ];

    await expect(validatePubKey(resultArr)).rejects.toMatchObject({
      code: TOPRFErrorCode.InvalidAuthToken,
    });
  });
});
