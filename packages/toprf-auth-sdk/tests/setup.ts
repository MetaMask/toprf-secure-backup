import { webcrypto } from 'crypto';
import nodeFetch from 'node-fetch';

// Make fetch available globally for CommonJS modules
global.fetch = nodeFetch as unknown as typeof global.fetch;
globalThis.fetch = nodeFetch as unknown as typeof globalThis.fetch;

// Make crypto available globally for CommonJS modules
/* eslint-disable n/no-unsupported-features/node-builtins */
global.crypto = webcrypto as unknown as typeof global.crypto;

/* eslint-disable n/no-unsupported-features/node-builtins */
globalThis.crypto = webcrypto as unknown as typeof globalThis.crypto;
