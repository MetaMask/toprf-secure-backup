export const JRPC_METHODS = {
  COMMITMENT_REQUEST: 'TOPRFCommitmentRequest',
  AUTHENTICATE_REQUEST: 'TOPRFAuthenticateRequest',
  STORE_KEY_SHARES_REQUEST: 'TOPRFStoreKeyShareRequest',
  RESET_RATE_LIMIT_REQUEST: 'TOPRFResetRateLimitRequest',
  TOPRF_EVAL_REQUEST: 'TOPRFEvalRequest',
  GET_PUB_KEY_REQUEST: 'TOPRFGetPubKeyRequest',
};

export const COMMIT_RESPONSE_THRESHOLD = 4;
export const AUTHENTICATION_THRESHOLD = 4;
/**
 * The number of nodes, a majority of the 5 nodes, that must report the same key state for it to
 * count. A partially failed key registration can leave the nodes disagreeing.
 */
export const KEY_STATE_MAJORITY_THRESHOLD = 3;
export const TOPRF_EVAL_THRESHOLD = 3;
export const GET_PUB_KEY_THRESHOLD = 3;
export const GENERATE_SHARE_THRESHOLD = 3;
export const FIRST_KEY_INDEX = 1;
export const MAX_PASSWORD_CHAIN_LENGTH = 10;
export const PW_BACKUP_ITEM_ID = 'PW_BACKUP';

/**
 * Optional SSS JSON-RPC request header used by the SSS service for client logging.
 */
export const WEB3_CLIENT_HEADER = 'x-web3-client';

/**
 * Data types for encrypted account data.
 */
export enum EncAccountDataType {
  PrimarySrp = 1,
  ImportedSrp = 2,
  ImportedPrivateKey = 3,
  /**
   * A key envelope (pbek/rbek) wrapping a vault key set. Stored in its own
   * partition with a content-hash item id; `itemId` must not be set.
   */
  KeyEnvelope = 4,
  /**
   * An envelope control record. Stored in its own partition with a
   * content-hash item id; `itemId` must not be set.
   */
  EnvelopeControl = 5,
}

export enum JsonRpcErrorCodes {
  ErrorCodeInvalidParams = -32602,
  ErrorCodeInternal = -32603,
}
