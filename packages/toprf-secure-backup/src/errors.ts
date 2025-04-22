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

export enum TORPFErrorCode {
  Default = 1000,
  InvalidAuthenticateResults = 1001,
  InvalidCommitResults = 1002,
  PwdInputRateLimitExceeded = 1003,
  InsufficientValidResponses = 1004,
  CouldNotDeriveThresholdAuthPubKey = 1005,
  CouldNotDeriveEncryptionKey = 1006,
  EndpointNotFound = 1007,
  InsufficientAuthTokens = 1008,
  RateLimitExceeded = 1009,
  InvalidAuthTokens = 1010,
  // AuthTokenExpired = 1011,
  JsonRpcError = 1012,
  CouldNotFetchPassword = 1013,
}

/**
 * T-OPRF error.
 */
export class TOPRFError extends Error implements ITOPRFError {
  code: number;

  meta?: Record<string, unknown>;

  protected static messages: Record<TORPFErrorCode, string> = {
    [TORPFErrorCode.Default]: 'Something went wrong.',
    [TORPFErrorCode.InvalidAuthenticateResults]:
      'Invalid authenticate results.',
    [TORPFErrorCode.InvalidCommitResults]: 'Invalid commit results.',
    [TORPFErrorCode.PwdInputRateLimitExceeded]:
      'Rate limit exceeded for password input attempts.',
    [TORPFErrorCode.InsufficientValidResponses]:
      'Insufficient valid responses.',
    [TORPFErrorCode.CouldNotDeriveThresholdAuthPubKey]:
      'Could not derive threshold auth pub key.',
    [TORPFErrorCode.CouldNotDeriveEncryptionKey]:
      'Could not derive encryption key.',
    [TORPFErrorCode.EndpointNotFound]: 'Endpoint not found.',
    [TORPFErrorCode.InsufficientAuthTokens]:
      'Insufficient number of auth tokens.',
    [TORPFErrorCode.RateLimitExceeded]: 'Rate limit error from server.',
    [TORPFErrorCode.InvalidAuthTokens]: 'Invalid auth tokens.',
    // [TORPFErrorCode.AuthTokenExpired]: 'Auth token expired.', // need to wait for the backend to update the error code
    [TORPFErrorCode.JsonRpcError]: 'Json rpc error.', // should/must specify error description in `error.data` field from the server response
    [TORPFErrorCode.CouldNotFetchPassword]: 'Could not fetch password.',
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
    code: TORPFErrorCode,
    extraMessage = '',
    meta?: Record<string, unknown>,
  ): ITOPRFError {
    const extendedMessage = extraMessage ? ` ${extraMessage}` : '';
    if (!TOPRFError.messages[code]) {
      return new TOPRFError(
        1000,
        `${TOPRFError.messages[TORPFErrorCode.Default]}${extendedMessage}`,
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
    return new TOPRFError(
      TORPFErrorCode.Default,
      `${TOPRFError.messages[TORPFErrorCode.Default]} ${extraMessage}`,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for invalid authenticate results.
   */
  public static invalidAuthenticateResults(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.InvalidAuthenticateResults,
      extraMessage,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for invalid commit results.
   */
  public static invalidCommitResults(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.InvalidCommitResults,
      extraMessage,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for rate limit exceeded for password input attempts.
   */
  public static pwdInputRateLimitExceeded(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.PwdInputRateLimitExceeded,
      extraMessage,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for insufficient valid responses.
   */
  public static insufficientValidResponses(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.InsufficientValidResponses,
      extraMessage,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for could not derive threshold auth pub key.
   */
  public static couldNotDeriveThresholdAuthPubKey(
    extraMessage = '',
  ): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.CouldNotDeriveThresholdAuthPubKey,
      extraMessage,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for could not derive encryption key.
   */
  public static couldNotDeriveEncryptionKey(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.CouldNotDeriveEncryptionKey,
      extraMessage,
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for endpoint not found.
   */
  public static endpointNotFound(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(TORPFErrorCode.EndpointNotFound, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for insufficient auth tokens.
   */
  public static insufficientAuthTokens(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.InsufficientAuthTokens,
      extraMessage,
    );
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
    return TOPRFError.fromCode(
      TORPFErrorCode.RateLimitExceeded,
      extraMessage || details.message,
      {
        rateLimitDetails: details,
      },
    );
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for invalid auth tokens.
   */
  public static invalidAuthTokens(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(TORPFErrorCode.InvalidAuthTokens, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for json rpc error.
   */
  public static jsonRpcError(extraMessage: string): ITOPRFError {
    return TOPRFError.fromCode(TORPFErrorCode.JsonRpcError, extraMessage);
  }

  /**
   *
   * @param extraMessage - The extra message of the error.
   * @returns - The error instance for could not fetch password.
   */
  public static couldNotFetchPassword(extraMessage = ''): ITOPRFError {
    return TOPRFError.fromCode(
      TORPFErrorCode.CouldNotFetchPassword,
      extraMessage,
    );
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
