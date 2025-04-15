import type { JSONRPCError } from '@metamask/auth-network-utils';

import { JsonRpcErrorCodes } from './constants';
import { TOPRFError } from './errors';
import { checkRateLimitErrors, parseJsonRpcError } from './utils';

describe('checkRateLimitErrors', () => {
  it('should return undefined for an empty array', () => {
    expect(checkRateLimitErrors([])).toBeUndefined();
  });

  it('should return undefined if no rate limit errors are found', () => {
    const results = [
      { result: 'success' },
      { error: { code: -32000, message: 'Internal error' } },
    ];

    expect(checkRateLimitErrors(results)).toBeUndefined();
  });

  it('should return undefined if rate limit errors have incorrect property types', () => {
    const results = [
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 123, // Wrong type - should be string
            remaining_time: 300,
            is_permanent: false,
          },
        },
      },
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: '300', // Wrong type - should be number
            is_permanent: false,
          },
        },
      },
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: 300,
            is_permanent: 'false', // Wrong type - should be boolean
          },
        },
      },
    ];

    expect(checkRateLimitErrors(results)).toBeUndefined();
  });

  it('should return rate limit details if a single rate limit error is found', () => {
    const results = [
      { result: 'success' },
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: 300,
            is_permanent: false,
          },
        },
      },
    ];

    const expected = {
      message: 'Too many requests',
      remainingTime: 300,
      isPermanent: false,
    };

    expect(checkRateLimitErrors(results)).toStrictEqual(expected);
  });

  it('should return the rate limit with the longest remaining time among multiple rate limits', () => {
    const results = [
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: 300,
            is_permanent: false,
          },
        },
      },
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: 600, // Longer time
            is_permanent: false,
          },
        },
      },
    ];

    const expected = {
      message: 'Too many requests',
      remainingTime: 600,
      isPermanent: false,
    };

    expect(checkRateLimitErrors(results)).toStrictEqual(expected);
  });

  it('should prioritize permanent rate limits over temporary ones', () => {
    const results = [
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: 1000, // Longer time but not permanent
            is_permanent: false,
          },
        },
      },
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Account suspended',
            remaining_time: 100, // Shorter time but permanent
            is_permanent: true,
          },
        },
      },
    ];

    const expected = {
      message: 'Account suspended',
      remainingTime: 100,
      isPermanent: true,
    };

    expect(checkRateLimitErrors(results)).toStrictEqual(expected);
  });

  it('should handle mixed error types', () => {
    const results = [
      { result: 'success' },
      { error: { code: -32000, message: 'Internal error' } },
      {
        error: {
          code: -32602,
          message: 'Rate limit exceeded',
          data: {
            message: 'Too many requests',
            remaining_time: 300,
            is_permanent: false,
          },
        },
      },
    ];

    const expected = {
      message: 'Too many requests',
      remainingTime: 300,
      isPermanent: false,
    };

    expect(checkRateLimitErrors(results)).toStrictEqual(expected);
  });

  it('should correctly parse JsonRpcError', () => {
    const invalidAuthTokenError: JSONRPCError = {
      code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
      message: 'Invalid auth tokens',
    };
    const error = parseJsonRpcError(invalidAuthTokenError);
    expect(error).toBeInstanceOf(TOPRFError);
    expect(error.code).toBe(1010);

    const invalidParamsErrorWithoutData: JSONRPCError = {
      code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
      message: 'Insufficient share import items: got 3, expected 4',
    };
    const error2 = parseJsonRpcError(invalidParamsErrorWithoutData);
    expect(error2).toBeInstanceOf(TOPRFError);
    expect(error2.code).toBe(1012);

    const invalidParamsErrorWithData: JSONRPCError = {
      code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
      message: 'Invalid params',
      data: 'Key change request invalid',
    };
    const error3 = parseJsonRpcError(invalidParamsErrorWithData);
    expect(error3).toBeInstanceOf(TOPRFError);
    expect(error3.code).toBe(1012);

    const invalidParamsErrorWithJsonData: JSONRPCError = {
      code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
      message: 'Invalid params',
      data: {
        details: 'Missing required fields',
      },
    };
    const error4 = parseJsonRpcError(invalidParamsErrorWithJsonData);
    expect(error4).toBeInstanceOf(TOPRFError);
    expect(error4.code).toBe(1012);

    const internalError: JSONRPCError = {
      code: JsonRpcErrorCodes.ErrorCodeInternal,
      message: 'Internal error',
      data: 'Failed to prepare nodes',
    };
    const error5 = parseJsonRpcError(internalError);
    expect(error5).toBeInstanceOf(TOPRFError);
    expect(error5.code).toBe(1012);

    const internalErrorWithoutData: JSONRPCError = {
      code: JsonRpcErrorCodes.ErrorCodeInternal,
      message: 'Internal error',
    };
    const error6 = parseJsonRpcError(internalErrorWithoutData);
    expect(error6).toBeInstanceOf(TOPRFError);
    expect(error6.code).toBe(1012);

    const unknownError: JSONRPCError = {
      code: -404,
      message: 'Unknown error',
    };
    const error7 = parseJsonRpcError(unknownError);
    expect(error7).toBeInstanceOf(TOPRFError);
    expect(error7.code).toBe(1000);
  });
});
