import nodeFetch from 'node-fetch';
import { webcrypto } from 'crypto';

// Make fetch available globally for CommonJS modules
global.fetch = nodeFetch as unknown as typeof global.fetch;
globalThis.fetch = nodeFetch as unknown as typeof globalThis.fetch;

// Make crypto available globally for CommonJS modules
global.crypto = webcrypto as unknown as typeof global.crypto;
globalThis.crypto = webcrypto as unknown as typeof globalThis.crypto;
