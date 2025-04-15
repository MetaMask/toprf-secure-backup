/**
 * Type for the rate limit error details
 */
export type RateLimitErrorData = {
  message: string;
  remainingTime: number;
  isPermanent: boolean;
};

export type ITOPRFError = Error & {
  code: number;
  meta?: Record<string, unknown>;
};

/**
 * T-OPRF error.
 */
export class TOPRFError extends Error implements ITOPRFError {
  code: number;

  meta?: Record<string, unknown>;

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
    1010: 'Invalid auth tokens.',
    // 1011: 'Auth token expired.', // need to wait for the backend to update the error code
    1012: 'Json rpc error.', // should/must specify error description in `error.data` field from the server response
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
    super(message);
    this.code = code;
    this.meta = meta;
    // Set name explicitly as minification can mangle class names
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

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for invalid auth tokens.
   */
  public static invalidAuthTokens(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1010, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for json rpc error.
   */
  public static jsonRpcError(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(1012, extraMessage);
  }

  /**
   * @returns - The JSON representation of the error data.
   */
  toJSON(): {
    name: string;
    code: number;
    message: string;
    meta?: Record<string, unknown>;
  } {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      meta: this.meta,
    };
  }

  /**
   * @returns - The string representation of the error.
   */
  toString(): string {
    return JSON.stringify(this.toJSON());
  }
}
