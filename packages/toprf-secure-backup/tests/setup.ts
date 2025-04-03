import nodeFetch from 'node-fetch';

// Make fetch available globally for CommonJS modules
global.fetch = nodeFetch as unknown as typeof global.fetch;
globalThis.fetch = nodeFetch as unknown as typeof globalThis.fetch;
