import type { JRPCResponse } from '@metamask/auth-network-utils';

export type CommitmentJRPCRequestParams = {
  message_prefix: string;
  token_commitment: string;
  verifier: string;
  temp_pub_key_x: string;
  temp_pub_key_y: string;
};

export type CommitmentJRPCRequest = {
  jsonrpc: string;
  method: string;
  id: number;
  params: CommitmentJRPCRequestParams;
};

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

export type AuthJRPCRequest = {
  jsonrpc: string;
  method: string;
  id: number;
  params: AuthJRPCRequestParams;
};

export type AuthRequestResult = {
  auth_token: string;
  node_index: number;
  enc_pub_key: string;
  enc_key_index: number;
};

export type AuthJRPCResponse = JRPCResponse<AuthRequestResult>;
