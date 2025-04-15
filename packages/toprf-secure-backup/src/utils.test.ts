import { checkRateLimitErrors } from './utils';

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
});
