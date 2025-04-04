"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EXISTING_USER_AUTHENTICATION_THRESHOLD = exports.NEW_USER_AUTHENTICATION_THRESHOLD = exports.COMMIT_RESPONSE_THRESHOLD = exports.COMMIT_RETRY_COUNT = exports.DEFAULT_METADATA_SERVER_URL = exports.NODE_URLS = exports.JRPC_METHODS = void 0;
exports.JRPC_METHODS = {
    COMMITMENT_REQUEST: 'TOPRFCommitmentRequest',
    AUTHENTICATE_REQUEST: 'TOPRFAuthenticateRequest',
    STORE_KEY_SHARES_REQUEST: 'TOPRFStoreKeyShareRequest',
    RESET_RATE_LIMIT_REQUEST: 'TOPRFResetRateLimitRequest',
    TOPRF_EVAL_REQUEST: 'TOPRFEvalRequest',
};
exports.NODE_URLS = [
    'https://node-1.dev-node.web3auth.io/sss/jrpc',
    'https://node-2.dev-node.web3auth.io/sss/jrpc',
    'https://node-3.dev-node.web3auth.io/sss/jrpc',
    'https://node-4.dev-node.web3auth.io/sss/jrpc',
    'https://node-5.dev-node.web3auth.io/sss/jrpc',
];
exports.DEFAULT_METADATA_SERVER_URL = 'https://node-2.dev-node.web3auth.io/metadata';
exports.COMMIT_RETRY_COUNT = 4;
exports.COMMIT_RESPONSE_THRESHOLD = 4;
exports.NEW_USER_AUTHENTICATION_THRESHOLD = 4;
exports.EXISTING_USER_AUTHENTICATION_THRESHOLD = 3;
//# sourceMappingURL=constants.cjs.map