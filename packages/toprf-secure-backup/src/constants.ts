export const JRPC_METHODS = {
  COMMITMENT_REQUEST: 'TOPRFCommitmentRequest',
  AUTHENTICATE_REQUEST: 'TOPRFAuthenticateRequest',
  STORE_KEY_SHARES_REQUEST: 'TOPRFStoreKeyShareRequest',
  RESET_RATE_LIMIT_REQUEST: 'TOPRFResetRateLimitRequest',
  TOPRF_EVAL_REQUEST: 'TOPRFEvalRequest',
};

export const METADATA_NODES_ENDPOINTS_MAP = {
  1: 'https://node-1.dev-node.web3auth.io/metadata',
  2: 'https://node-2.dev-node.web3auth.io/metadata',
  3: 'https://node-3.dev-node.web3auth.io/metadata',
  4: 'https://node-4.dev-node.web3auth.io/metadata',
  5: 'https://node-5.dev-node.web3auth.io/metadata',
};
export const COMMIT_RESPONSE_THRESHOLD = 4;
export const NEW_USER_AUTHENTICATION_THRESHOLD = 4;
export const EXISTING_USER_AUTHENTICATION_THRESHOLD = 3;
