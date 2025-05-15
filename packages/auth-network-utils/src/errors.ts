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
  toString(): string {
    return this.message;
  }
}
