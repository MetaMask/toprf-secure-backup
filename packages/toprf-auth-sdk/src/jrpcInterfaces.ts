import type {
  JRPCResponse,
  JRPCRequest,
  EciesHex,
} from '@metamask/auth-network-utils';

export type CommitmentJRPCRequestParams = {
  message_prefix: string;
  token_commitment: string;
  verifier: string;
  temp_pub_key_x: string;
  temp_pub_key_y: string;
};

export type CommitmentJRPCRequest = JRPCRequest<CommitmentJRPCRequestParams>;

export type CommitmentRequestResult = {
  signature: string;
  data: string;
  node_pub_x: string;
  node_pub_y: string;
  node_index: number;
};

export type CommitmentJRPCResponse = JRPCResponse<CommitmentRequestResult>;

export type AuthJRPCRequestParams = {
  auth_data: {
    authentication_context: {
      id_token: string;
      verifier: string;
      verifier_id: string;
    };
    verifier_oauth_params: Record<string, unknown>;
  };
  commitment_signatures: CommitmentRequestResult[];
  client_time: string;
};

export type AuthJRPCRequest = JRPCRequest<AuthJRPCRequestParams>;

export type AuthRequestResult = {
  auth_token: string;
  node_index: number;
  pub_key: string;
  key_index: number;
};

export type AuthJRPCResponse = JRPCResponse<AuthRequestResult>;

export type ShareImportItem = {
  encrypted_share: string;
  encrypted_share_metadata: EciesHex;
  share_key_index: number;
  node_index: number;
  sss_endpoint: string;
};

export type StoreKeySharesJRPCRequestParams = {
  verifier: string;
  verifier_id: string;
  auth_token: string;
  pub_key: string;
  share_import_items: ShareImportItem[];
};

export type StoreKeySharesJRPCRequest =
  JRPCRequest<StoreKeySharesJRPCRequestParams>;

export type StoreKeySharesJRPCResponse = JRPCResponse<void>;
