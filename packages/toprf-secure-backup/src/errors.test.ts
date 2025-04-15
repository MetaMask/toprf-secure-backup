import {
  TOPRFError,
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
    const error = TOPRFError.fromCode(unknownCode, extraMessage);
    const { message: expectedBaseMessage } = TOPRFError.default();

    expect(error.code).toBe(1000);
    expect(error.message).toContain(expectedBaseMessage);
    expect(error.message).toContain(extraMessage);
    expect(error.meta).toBeUndefined();
  });

  it('should create a default error using the default() static method', () => {
    const extraMessage = 'Default issue';
    const error = TOPRFError.default(extraMessage);
    const { message: expectedBaseMessage } = TOPRFError.default();

    expect(error.code).toBe(1000);
    expect(error.message).toContain(expectedBaseMessage);
    expect(error.message).toContain(extraMessage);
    expect(error.meta).toBeUndefined();
  });

  it('should create specific errors using static factory methods', () => {
    expect(TOPRFError.invalidAuthenticateResults().code).toBe(1001);
    expect(TOPRFError.invalidCommitResults().code).toBe(1002);
    expect(TOPRFError.pwdInputRateLimitExceeded().code).toBe(1003);
    expect(TOPRFError.insufficientValidResponses().code).toBe(1004);
    expect(TOPRFError.couldNotDeriveThresholdAuthPubKey().code).toBe(1005);
    expect(TOPRFError.couldNotDeriveEncryptionKey().code).toBe(1006);
    expect(TOPRFError.endpointNotFound().code).toBe(1007);
    expect(TOPRFError.insufficientAuthTokens().code).toBe(1008);
  });

  it('should create a rate limit error with details', () => {
    const details: RateLimitErrorData = {
      message: 'Rate limit hit',
      remainingTime: 60,
      isPermanent: false,
    };
    const extraMessage = 'Please try again later';
    const error = TOPRFError.rateLimitExceeded(details, extraMessage);

    expect(error.code).toBe(1009);
    expect(error.message).toContain(extraMessage);
    expect(error.meta?.rateLimitDetails).toStrictEqual(details);
  });

  it('should create a rate limit error using details message if no extra message provided', () => {
    const details: RateLimitErrorData = {
      message: 'Server rate limit message',
      remainingTime: 120,
      isPermanent: true,
    };
    const error = TOPRFError.rateLimitExceeded(details);

    expect(error.code).toBe(1009);
    expect(error.message).toContain(details.message);
    expect(error.meta?.rateLimitDetails).toStrictEqual(details);
  });

  it('should serialize to JSON correctly using toJSON() including stack', () => {
    const code = 1004;
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
    const code = 1005;
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
