export const JRPC_METHODS = {
  COMMITMENT_REQUEST: 'TOPRFCommitmentRequest',
  AUTHENTICATE_REQUEST: 'TOPRFAuthenticateRequest',
  STORE_KEY_SHARES_REQUEST: 'TOPRFStoreKeyShareRequest',
  RESET_RATE_LIMIT_REQUEST: 'TOPRFResetRateLimitRequest',
  TOPRF_EVAL_REQUEST: 'TOPRFEvalRequest',
};

export const NODE_URLS = [
  'https://node-1.dev-node.web3auth.io/sss/jrpc',
  'https://node-2.dev-node.web3auth.io/sss/jrpc',
  'https://node-3.dev-node.web3auth.io/sss/jrpc',
  'https://node-4.dev-node.web3auth.io/sss/jrpc',
  'https://node-5.dev-node.web3auth.io/sss/jrpc',
];

export const DEFAULT_METADATA_SERVER_URL =
  'https://node-2.dev-node.web3auth.io/metadata';
export const COMMIT_RETRY_COUNT = 4;
export const COMMIT_RESPONSE_THRESHOLD = 4;
export const NEW_USER_AUTHENTICATION_THRESHOLD = 4;
export const EXISTING_USER_AUTHENTICATION_THRESHOLD = 3;
