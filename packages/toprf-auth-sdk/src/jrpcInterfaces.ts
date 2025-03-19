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
