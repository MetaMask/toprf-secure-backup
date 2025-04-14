/**
 * Type for the rate limit error details
 */
export type RateLimitErrorData = {
  message: string;
  remainingTime: number;
  isPermanent: boolean;
};

type ITOPRFError = {
  name: string;
  code: number;
  message: string;
  meta?: Record<string, unknown>;
  toString(): string;
} & CustomError;

/**
 * Error class for handling errors from `some` function promises.
 */
export class SomeError<TResponse> extends Error {
  errors: (Error | undefined)[];

  responses: TResponse[];

  predicate: Error | undefined;

  /**
   *
   * @param options0 - options.
   * @param options0.errors - errors collected from promises.
   * @param options0.responses - responses collected from promises.
   * @param options0.predicate - predicate error object that caused the failure.
   */
  constructor({
    errors,
    responses,
    predicate,
  }: {
    errors: (Error | undefined)[];
    responses: TResponse[];
    predicate: Error | undefined;
  }) {
    // its fine to log responses in errors logs for better debugging,
    // as data is always encrypted with temp key
    // temp key should not be logged anywhere
    const predicateMessage = predicate?.message ?? 'unknown error';
    const message = `Unable to resolve enough promises. 
      errors: ${errors.map((er: Error | undefined) => er?.message ?? er).join(', ')}, 
      predicate error: ${predicateMessage},
      ${responses.length} responses,
      responses: ${JSON.stringify(responses)}`;
    super(message);
    this.errors = errors;
    this.responses = responses;
    this.predicate = predicate;
    Object.setPrototypeOf(this, SomeError.prototype);
  }

  /**
   * @returns - message with errors and responses from all promises.
   */
  get message(): string {
    const predicateMessage = this.predicate?.message ?? 'unknown error';
    return `${super.message}. errors: ${this.errors.map((er: Error | undefined) => er?.message ?? er).join(', ')} and ${
      this.responses.length
    } responses: ${JSON.stringify(this.responses)},
      predicate error: ${predicateMessage}`;
  }

  /**
   * @returns - message with errors and responses from all promises.
   */
  toString(): string {
    return this.message;
  }
}

/**
 * Fix the prototype chain of the error
 *
 * Use Object.setPrototypeOf
 * Support ES6 environments
 *
 * Fallback setting __proto__
 * Support IE11+, see https://docs.microsoft.com/en-us/scripting/javascript/reference/javascript-version-information
 *
 * @param target - The target error.
 * @param prototype - The prototype of the error.
 */
function fixProto(target: Error, prototype: object): void {
  const { setPrototypeOf } = Object;
  if (setPrototypeOf) {
    setPrototypeOf(target, prototype);
  } else {
    // eslint-disable-next-line no-proto
    (target as any).__proto__ = prototype;
  }
}

/**
 * Capture and fix the error stack when available
 *
 * Use Error.captureStackTrace
 * Support v8 environments
 *
 * @param target - The target error.
 * @param fn - The function to capture the stack trace.
 */
function fixStack(target: Error, fn = target.constructor): void {
  if (Error.captureStackTrace) {
    Error.captureStackTrace(target, fn);
  }
}

/**
 * Custom error class.
 */
export class CustomError extends Error {
  /**
   * Optional meta object that can contain any additional error details
   */
  meta?: Record<string, unknown>;

  /**
   * @param message - The message of the error.
   * @param meta - Optional meta object with additional error details
   */
  constructor(message?: string, meta?: Record<string, unknown>) {
    super(message);
    // set error name as constructor name, make it not enumerable to keep native Error behavior
    // see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/new.target#new.target_in_constructors
    // see https://github.com/adriengibrat/ts-custom-error/issues/30
    Object.defineProperty(this, 'name', {
      value: new.target.name,
      enumerable: false,
      configurable: true,
    });
    // fix the extended error prototype chain
    // because typescript __extends implementation can't
    // see https://github.com/Microsoft/TypeScript-wiki/blob/master/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
    fixProto(this, new.target.prototype);
    // try to remove contructor from stack trace
    fixStack(this);

    this.meta = meta;
  }
}

/**
 * Base class for all T-OPRF errors.
 */
abstract class AbstractTOPRFError extends CustomError implements ITOPRFError {
  code: number;

  message: string;

  /**
   *
   * @param code - The code of the error.
   * @param message - The message of the error.
   * @param meta - Optional meta for the error.
   */
  public constructor(
    code: number,
    message: string,
    meta?: Record<string, unknown>,
  ) {
    super(message, meta);

    this.code = code;
    this.message = message || '';
    // Set name explicitly as minification can mangle class names
    Object.defineProperty(this, 'name', { value: 'TOPRFSecureBackupError' });
  }

  /**
   * @returns - The JSON representation of the error.
   */
  toJSON(): ITOPRFError {
    const result: Omit<ITOPRFError, 'toString'> = {
      name: this.name,
      code: this.code,
      message: this.message,
      meta: this.meta,
    };

    return result as ITOPRFError;
  }

  /**
   * @returns - The string representation of the error.
   */
  toString(): string {
    return JSON.stringify(this.toJSON());
  }
}

/**
 * T-OPRF error.
 */
export class TOPRFError extends AbstractTOPRFError {
  protected static messages: { [key: number]: string } = {
    1000: 'Something went wrong.',
    1001: 'Invalid authenticate results.',
    1002: 'Invalid commit results.',
    1003: 'Rate limit exceeded for password input attempts.',
    1004: 'Insufficient valid responses.',
    1005: 'Could not derive threshold auth pub key.',
    1006: 'Could not derive encryption key.',
    1007: 'Endpoint not found.',
    1008: 'Insufficient number of auth tokens.',
    1009: 'Rate limit error from server.',
  };

  /**
   *
   * @param code - The code of the error.
   * @param message - The message of the error.
   * @param meta - Optional meta for the error.
   */
  public constructor(
    code: number,
    message: string,
    meta?: Record<string, unknown>,
  ) {
    super(code, message, meta);
    Object.defineProperty(this, 'name', { value: 'TOPRFError' });
  }

  /**
   *
   * @param code - The code of the error.
   * @param extraMessage - The extra message of the error.
   * @param meta - Optional meta for the error.
   * @returns - The error for the given code.
   */
  public static fromCode(
    code: number,
    extraMessage = '',
    meta?: Record<string, unknown>,
  ): ITOPRFError {
    const extendedMessage = extraMessage ? ` ${extraMessage}` : '';
    if (!TOPRFError.messages[code]) {
      return new TOPRFError(
        1000,
        `${TOPRFError.messages[1000]}${extendedMessage}`,
        meta,
      );
    }
    return new TOPRFError(
      code,
      `${TOPRFError.messages[code]}${extendedMessage}`,
      meta,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The default error.
   */
  public static default(extraMessage = ''): ITOPRFError {
    return new TOPRFError(1000, `${TOPRFError.messages[1000]} ${extraMessage}`);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for invalid authenticate results.
   */
  public static invalidAuthenticateResults(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1001, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for invalid commit results.
   */
  public static invalidCommitResults(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1002, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for rate limit exceeded for password input attempts.
   */
  public static pwdInputRateLimitExceeded(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1003, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for insufficient valid responses.
   */
  public static insufficientValidResponses(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1004, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for could not derive threshold auth pub key.
   */
  public static couldNotDeriveThresholdAuthPubKey(
    extraMessage = '',
  ): ITOPRFError {
    return TOPRFError.fromCode(1005, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for could not derive encryption key.
   */
  public static couldNotDeriveEncryptionKey(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1006, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for endpoint not found.
   */
  public static endpointNotFound(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1007, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for insufficient auth tokens.
   */
  public static insufficientAuthTokens(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1008, extraMessage);
  }

  /**
   * Creates a rate limit error with details from the server
   *
   * @param details - Details about the rate limit from the server
   * @param details.message - The error message from the server
   * @param details.remainingTime - Remaining time in seconds before retrying is allowed
   * @param details.isPermanent - Whether the rate limit is permanent
   * @param extraMessage - Additional message to include in the error
   * @returns - The error instance for rate limit exceeded
   */
  public static rateLimitExceeded(
    details: RateLimitErrorData,
    extraMessage = '',
  ): ITOPRFError {
    return TOPRFError.fromCode(1009, extraMessage || details.message, {
      rateLimitDetails: details,
    });
  }
}
