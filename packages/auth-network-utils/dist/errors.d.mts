/**
 * Error class for handling errors from `some` function promises.
 */
export declare class SomeError<TResponse> extends Error {
    errors: (Error | undefined)[];
    responses: TResponse[];
    predicate: string;
    /**
     *
     * @param options0 - options.
     * @param options0.errors - errors collected from promises.
     * @param options0.responses - responses collected from promises.
     * @param options0.predicate - predicate that failed.
     */
    constructor({ errors, responses, predicate, }: {
        errors: (Error | undefined)[];
        responses: TResponse[];
        predicate: string;
    });
    /**
     * @returns - message with errors and responses from all promises.
     */
    get message(): string;
    /**
     * @returns - message with errors and responses from all promises.
     */
    toString(): string;
}
/**
 * Custom error class.
 */
export declare class CustomError extends Error {
    /**
     *
     * @param message - The message of the error.
     */
    constructor(message?: string);
}
type ITOPRFError = {
    name: string;
    code: number;
    message: string;
    toString(): string;
} & CustomError;
/**
 * Base class for all T-OPRF errors.
 */
declare abstract class AbstractTOPRFError extends CustomError implements ITOPRFError {
    code: number;
    message: string;
    /**
     *
     * @param code - The code of the error.
     * @param message - The message of the error.
     */
    constructor(code: number, message: string);
    /**
     * @returns - The JSON representation of the error.
     */
    toJSON(): ITOPRFError;
    /**
     * @returns - The string representation of the error.
     */
    toString(): string;
}
/**
 * T-OPRF error.
 */
export declare class TOPRFError extends AbstractTOPRFError {
    protected static messages: {
        [key: number]: string;
    };
    /**
     *
     * @param code - The code of the error.
     * @param message - The message of the error.
     */
    constructor(code: number, message: string);
    /**
     *
     * @param code - The code of the error.
     * @param extraMessage - The extra message of the error.
     * @returns - The error for the given code.
     */
    static fromCode(code: number, extraMessage?: string): ITOPRFError;
    /**
     *
     * @param extraMessage - The extra message of the error.
     * @returns - The default error.
     */
    static default(extraMessage?: string): ITOPRFError;
    /**
     *
     * @param extraMessage - The extra message of the error.
     * @returns - The error instance for invalid authenticate results.
     */
    static invalidAuthenticateResults(extraMessage?: string): ITOPRFError;
}
export {};
//# sourceMappingURL=errors.d.mts.map