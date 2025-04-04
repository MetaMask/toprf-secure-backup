"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TOPRFError = exports.CustomError = exports.SomeError = void 0;
/**
 * Error class for handling errors from `some` function promises.
 */
class SomeError extends Error {
    /**
     *
     * @param options0 - options.
     * @param options0.errors - errors collected from promises.
     * @param options0.responses - responses collected from promises.
     * @param options0.predicate - predicate that failed.
     */
    constructor({ errors, responses, predicate, }) {
        // its fine to log responses in errors logs for better debugging,
        // as data is always encrypted with temp key
        // temp key should not be logged anywhere
        const message = `Unable to resolve enough promises. 
      errors: ${errors.map((er) => er?.message ?? er).join(', ')}, 
      predicate error: ${predicate},
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
    get message() {
        return `${super.message}. errors: ${this.errors.map((er) => er?.message ?? er).join(', ')} and ${this.responses.length} responses: ${JSON.stringify(this.responses)},
      predicate error: ${this.predicate}`;
    }
    /**
     * @returns - message with errors and responses from all promises.
     */
    toString() {
        return this.message;
    }
}
exports.SomeError = SomeError;
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
function fixProto(target, prototype) {
    const { setPrototypeOf } = Object;
    if (setPrototypeOf) {
        setPrototypeOf(target, prototype);
    }
    else {
        // eslint-disable-next-line no-proto
        target.__proto__ = prototype;
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
function fixStack(target, fn = target.constructor) {
    if (Error.captureStackTrace) {
        Error.captureStackTrace(target, fn);
    }
}
/**
 * Custom error class.
 */
class CustomError extends Error {
    /**
     *
     * @param message - The message of the error.
     */
    constructor(message) {
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
    }
}
exports.CustomError = CustomError;
/**
 * Base class for all T-OPRF errors.
 */
class AbstractTOPRFError extends CustomError {
    /**
     *
     * @param code - The code of the error.
     * @param message - The message of the error.
     */
    constructor(code, message) {
        // takes care of stack and proto
        super(message);
        this.code = code;
        this.message = message || '';
        // Set name explicitly as minification can mangle class names
        Object.defineProperty(this, 'name', { value: 'TOPRFSecureBackupError' });
    }
    /**
     * @returns - The JSON representation of the error.
     */
    toJSON() {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
        };
    }
    /**
     * @returns - The string representation of the error.
     */
    toString() {
        return JSON.stringify(this.toJSON());
    }
}
/**
 * T-OPRF error.
 */
class TOPRFError extends AbstractTOPRFError {
    /**
     *
     * @param code - The code of the error.
     * @param message - The message of the error.
     */
    constructor(code, message) {
        super(code, message);
        Object.defineProperty(this, 'name', { value: 'TOPRFError' });
    }
    /**
     *
     * @param code - The code of the error.
     * @param extraMessage - The extra message of the error.
     * @returns - The error for the given code.
     */
    static fromCode(code, extraMessage = '') {
        const extendedMessage = extraMessage ? ` ${extraMessage}` : '';
        if (!TOPRFError.messages[code]) {
            return new TOPRFError(1000, `${TOPRFError.messages[1000]}${extendedMessage}`);
        }
        return new TOPRFError(code, `${TOPRFError.messages[code]}${extendedMessage}`);
    }
    /**
     *
     * @param extraMessage - The extra message of the error.
     * @returns - The default error.
     */
    static default(extraMessage = '') {
        return new TOPRFError(1000, `${TOPRFError.messages[1000]} ${extraMessage}`);
    }
    /**
     *
     * @param extraMessage - The extra message of the error.
     * @returns - The error instance for invalid authenticate results.
     */
    static invalidAuthenticateResults(extraMessage = '') {
        return TOPRFError.fromCode(1001, extraMessage);
    }
}
exports.TOPRFError = TOPRFError;
TOPRFError.messages = {
    1000: 'Something went wrong.',
    1001: 'Invalid authenticate results.',
};
//# sourceMappingURL=errors.cjs.map