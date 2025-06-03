import type { JSONRPCError } from '@metamask/auth-network-utils';

import { JsonRpcErrorCodes } from './constants';
import { TOPRFError, TOPRFErrorCode } from './errors';
import type { ToprfEvalJRPCResponse } from './jrpcInterfaces';
import {
  checkRateLimitErrors,
  extractRateLimitErrorFromResults,
  getTOPRFError,
  parseJsonRpcError,
} from './utils';

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
            lock_time: 60,
            guess_count: 5,
          },
        },
      },
    ];

    const expected = {
      message: 'Too many requests',
      remainingTime: 300,
      lockTime: 60,
      guessCount: 5,
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
            lock_time: 60,
            guess_count: 5,
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
            lock_time: 120,
            guess_count: 6,
          },
        },
      },
    ];

    const expected = {
      message: 'Too many requests',
      remainingTime: 600,
      lockTime: 120,
      guessCount: 6,
    };

    expect(checkRateLimitErrors(results)).toStrictEqual(expected);
  });

  it('should correctly extract rate limit details from a JSON-RPC response', () => {
    const toprfEvalResponses: ToprfEvalJRPCResponse[] = Array(4)
      .fill(0)
      .map((_, i) => ({
        jsonrpc: '2.0',
        id: 1,
        result: {
          blindedOutputX: 'abc',
          blindedOutputY: 'def',
          nodeIndex: i + 1,
          keyShareIndex: 1,
          pubKey: `pubKey${i}`,
          guessCount: 1,
          lockTimeSeconds: 0,
        },
      }));

    expect(
      extractRateLimitErrorFromResults(toprfEvalResponses),
    ).toBeUndefined();

    const toprfEvalResponsesWithRateLimit: ToprfEvalJRPCResponse[] = Array(4)
      .fill(0)
      .map((_, i) => ({
        jsonrpc: '2.0',
        id: 1,
        result: {
          blindedOutputX: 'abc',
          blindedOutputY: 'def',
          nodeIndex: i + 1,
          keyShareIndex: 1,
          pubKey: `pubKey${i}`,
          guessCount: 3,
          lockTimeSeconds: 30,
        },
      }));

    const rateLimitDetails = extractRateLimitErrorFromResults(
      toprfEvalResponsesWithRateLimit,
    );
    expect(rateLimitDetails).toBeDefined();
    expect(rateLimitDetails?.remainingTime).toBe(30);
    expect(rateLimitDetails?.guessCount).toBe(3);
    expect(rateLimitDetails?.lockTime).toBe(30);
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
            lock_time: 300,
            guess_count: 5,
          },
        },
      },
    ];

    const expected = {
      message: 'Too many requests',
      remainingTime: 300,
      lockTime: 300,
      guessCount: 5,
    };

    expect(checkRateLimitErrors(results)).toStrictEqual(expected);
  });

  describe('parseJsonRpcError', () => {
    it('should parse "Invalid auth tokens" message correctly', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
        message: 'Invalid auth token',
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.InvalidAuthToken);
      expect(parsedError.message).toContain('Invalid auth token');
    });

    it('should parse "Auth token expired" message correctly', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInvalidParams, // -32602
        message: 'Auth token expired.',
      };
      const expectedError = TOPRFError.authTokenExpired();
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(expectedError.code);
      expect(parsedError.message).toContain('Auth token expired');
    });

    it('should prioritize "Auth token expired" over "Invalid auth token"', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
        message: 'Error: Invalid auth token: auth token expired.',
      };
      const expectedError = TOPRFError.authTokenExpired(); // Expect expired error
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(expectedError.code);
      expect(parsedError.message).toContain('Auth token expired');
    });

    it('should parse InvalidParams error without data as JsonRpcError', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
        message: 'Insufficient share import items: got 3, expected 4',
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.JsonRpcError);
      expect(parsedError.message).toContain('Insufficient share import items');
    });

    it('should parse InvalidParams error with string data as JsonRpcError', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
        message: 'Invalid params',
        data: 'Key change request invalid',
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.JsonRpcError);
      expect(parsedError.message).toContain('Key change request invalid');
    });

    it('should parse InvalidParams error with JSON data as JsonRpcError', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInvalidParams,
        message: 'Invalid params',
        data: {
          details: 'Missing required fields',
        },
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.JsonRpcError);
      expect(parsedError.message).toContain('Missing required fields');
    });

    it('should parse Internal error with data as JsonRpcError', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInternal,
        message: 'Internal error',
        data: 'Failed to prepare nodes',
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.JsonRpcError);
      expect(parsedError.message).toContain('Failed to prepare nodes');
    });

    it('should parse Internal error without data as JsonRpcError', () => {
      const rpcError: JSONRPCError = {
        code: JsonRpcErrorCodes.ErrorCodeInternal,
        message: 'Internal error',
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.JsonRpcError);
      expect(parsedError.message).toContain('Internal error');
    });

    it('should parse unknown error codes as Default error', () => {
      const rpcError: JSONRPCError = {
        code: -404,
        message: 'Unknown error',
      };
      const parsedError = parseJsonRpcError(rpcError);
      expect(parsedError).toBeInstanceOf(TOPRFError);
      expect(parsedError.code).toBe(TOPRFErrorCode.Default);
      expect(parsedError.message).toContain('Unknown error');
    });
  });

  it('should be able to parse TOPRFError from SomeError', () => {
    const someError = TOPRFError.default('Test error');
    const error = getTOPRFError(someError);
    expect(error).toBeInstanceOf(TOPRFError);
    expect((error as TOPRFError).code).toBe(TOPRFErrorCode.Default);

    // Test with a non-TOPRFError
    const nonTOPRFError = new Error('Test error');
    const error2 = getTOPRFError(nonTOPRFError);
    expect(error2).toBe(nonTOPRFError);
  });
});
