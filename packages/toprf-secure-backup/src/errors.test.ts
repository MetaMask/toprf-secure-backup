import {
  TOPRFError,
  TOPRFErrorCode,
  type ITOPRFError,
  type RateLimitErrorData,
} from './errors';

describe('TOPRFError', () => {
  it('should create an error with a specific code and message', () => {
    const code = 1001;
    const extraMessage = 'Something specific went wrong';
    const meta = { detail: 'some detail' };
    const error = TOPRFError.fromCode(code, extraMessage, meta);
    const { message: expectedBaseMessage } = TOPRFError.fromCode(code);

    expect(error).toBeInstanceOf(TOPRFError);
    expect(error.code).toBe(code);
    expect(error.message).toContain(expectedBaseMessage);
    expect(error.message).toContain(extraMessage);
    expect(error.meta).toStrictEqual(meta);
    expect(error.name).toBe('TOPRFError');
  });

  it('should create a default error using fromCode with an unknown code', () => {
    const unknownCode = 9999;
    const extraMessage = 'Unknown issue';
    // @ts-expect-error - Intentional providing an invalid value
    const error = TOPRFError.fromCode(unknownCode, extraMessage);
    const { message: expectedBaseMessage } = TOPRFError.default();

    expect(error.code).toBe(TOPRFErrorCode.Default);
    expect(error.message).toContain(expectedBaseMessage);
    expect(error.message).toContain(extraMessage);
    expect(error.meta).toBeUndefined();
  });

  it('should create a default error using the default() static method', () => {
    const extraMessage = 'Default issue';
    const error = TOPRFError.default(extraMessage);
    const { message: expectedBaseMessage } = TOPRFError.default();

    expect(error.code).toBe(TOPRFErrorCode.Default);
    expect(error.message).toContain(expectedBaseMessage);
    expect(error.message).toContain(extraMessage);
    expect(error.meta).toBeUndefined();
  });

  it('should create specific errors using static factory methods', () => {
    expect(TOPRFError.invalidAuthenticateResults().code).toBe(
      TOPRFErrorCode.InvalidAuthenticateResults,
    );
    expect(TOPRFError.invalidCommitResults().code).toBe(
      TOPRFErrorCode.InvalidCommitResults,
    );
    expect(TOPRFError.pwdInputRateLimitExceeded().code).toBe(
      TOPRFErrorCode.PwdInputRateLimitExceeded,
    );
    expect(TOPRFError.insufficientValidResponses().code).toBe(
      TOPRFErrorCode.InsufficientValidResponses,
    );
    expect(TOPRFError.couldNotDeriveThresholdAuthPubKey().code).toBe(
      TOPRFErrorCode.CouldNotDeriveThresholdAuthPubKey,
    );
    expect(TOPRFError.couldNotDeriveEncryptionKey().code).toBe(
      TOPRFErrorCode.CouldNotDeriveEncryptionKey,
    );
    expect(TOPRFError.endpointNotFound().code).toBe(
      TOPRFErrorCode.EndpointNotFound,
    );
    expect(TOPRFError.insufficientAuthTokens().code).toBe(
      TOPRFErrorCode.InsufficientAuthTokens,
    );
    expect(TOPRFError.invalidAuthToken().code).toBe(
      TOPRFErrorCode.InvalidAuthToken,
    );
    expect(TOPRFError.couldNotFetchPassword().code).toBe(
      TOPRFErrorCode.CouldNotFetchPassword,
    );
  });

  it('should create a rate limit error with details', () => {
    const details: RateLimitErrorData = {
      message: 'Rate limit hit',
      remainingTime: 60,
      lockTime: 60,
      guessCount: 5,
    };
    const extraMessage = 'Please try again later';
    const error = TOPRFError.rateLimitExceeded(details, extraMessage);

    expect(error.code).toBe(TOPRFErrorCode.RateLimitExceeded);
    expect(error.message).toContain(extraMessage);
    expect(error.meta?.rateLimitDetails).toStrictEqual(details);
  });

  it('should create a rate limit error using details message if no extra message provided', () => {
    const details: RateLimitErrorData = {
      message: 'Server rate limit message',
      remainingTime: 120,
      lockTime: 120,
      guessCount: 6,
    };
    const error = TOPRFError.rateLimitExceeded(details);

    expect(error.code).toBe(TOPRFErrorCode.RateLimitExceeded);
    expect(error.message).toContain(details.message);
    expect(error.meta?.rateLimitDetails).toStrictEqual(details);
  });

  it('should serialize to JSON correctly using toJSON() including stack', () => {
    const code = TOPRFErrorCode.InsufficientValidResponses;
    const { message } = TOPRFError.fromCode(code);
    const meta = { data: 'metadata' };
    const error = new TOPRFError(code, message, meta);
    const {
      name,
      code: actualCode,
      message: actualMessage,
      meta: actualMeta,
    } = (error as any).toJSON();

    expect(name).toBe('TOPRFError');
    expect(actualCode).toBe(code);
    expect(actualMessage).toBe(message);
    expect(actualMeta).toStrictEqual(meta);
  });

  it('should serialize to JSON string correctly using toString()', () => {
    const code = TOPRFErrorCode.CouldNotDeriveThresholdAuthPubKey;
    const { message } = TOPRFError.fromCode(code);
    const meta = { key: 'value' };
    const error = new TOPRFError(code, message, meta);
    const errorString = error.toString();
    const {
      name,
      code: actualCode,
      message: actualMessage,
      meta: actualMeta,
    } = JSON.parse(errorString);

    expect(name).toBe('TOPRFError');
    expect(actualCode).toBe(code);
    expect(actualMessage).toBe(message);
    expect(actualMeta).toStrictEqual(meta);
  });

  it('should implement the ITOPRFError interface', () => {
    const error: ITOPRFError = TOPRFError.default();
    expect(error).toBeDefined();
    expect(error).toBeInstanceOf(Error);
    expect(typeof error.code).toBe('number');
  });
});
