/**
 *
 */
export class SomeError<T> extends Error {
  errors: (Error | undefined)[];

  responses: T[];

  predicate: string;

  /**
   *
   * @param options0 - options.
   * @param options0.errors - errors collected from promises.
   * @param options0.responses - responses collected from promises.
   * @param options0.predicate - predicate that failed.
   */
  constructor({
    errors,
    responses,
    predicate,
  }: {
    errors: (Error | undefined)[];
    responses: T[];
    predicate: string;
  }) {
    // its fine to log responses in errors logs for better debugging,
    // as data is always encrypted with temp key
    // temp key should not be logged anywhere
    const message = `Unable to resolve enough promises. 
      errors: ${errors.map((x) => x?.message || x).join(', ')}, 
      predicate error: ${predicate},
      ${responses.length} responses,
      responses: ${JSON.stringify(responses)}`;
    super(message);
    this.errors = errors;
    this.responses = responses;
    this.predicate = predicate;
  }

  /**
   * @returns - message with errors and responses from all promises.
   */
  get message(): string {
    return `${super.message}. errors: ${this.errors.map((x) => x?.message || x).join(', ')} and ${
      this.responses.length
    } responses: ${JSON.stringify(this.responses)},
      predicate error: ${this.predicate}`;
  }

  /**
   * @returns - message with errors and responses from all promises.
   */
  toString(): string {
    return this.message;
  }
}
