import type { JRPCResponse, JRPCRequest } from '@metamask/auth-network-utils';

export type CommitmentJRPCRequestParams = {
  tokenCommitment: string;
  verifier: string;
  tempPubKeyX: string;
  tempPubKeyY: string;
};

export type CommitmentJRPCRequest = JRPCRequest<CommitmentJRPCRequestParams>;

export type CommitmentRequestResult = {
  signature: string;
  data: string;
  nodePubX: string;
  nodePubY: string;
  nodeIndex: number;
};

export type CommitmentJRPCResponse = JRPCResponse<
  CommitmentRequestResult | undefined
>;

export type AuthJRPCRequestParams = {
  authData: {
    authenticationContext: {
      idToken: string;
      verifier: string;
      verifierId: string;
    };
    extraOauthParams?: Record<string, string | number | boolean>;
  };
  commitmentSignatures: CommitmentRequestResult[];
  clientTime: string;
};

export type AuthJRPCRequest = JRPCRequest<AuthJRPCRequestParams>;

export type AuthRequestResult = {
  authToken: string;
  nodeIndex: number;
  nodePubKey: string;
  pubKey: string;
  keyIndex: number;
};

export type AuthJRPCResponse = JRPCResponse<AuthRequestResult>;

export type ShareImportItem = {
  encryptedAuthToken: string;
  encryptedShare: string;
  shareKeyIndex: number;
  nodeIndex: number;
  sssEndpoint: string;
};

export type StoreKeySharesJRPCRequestParams = {
  verifier: string;
  verifierId: string;
  pubKey: string;
  shareImportItems: ShareImportItem[];
};

export type StoreKeySharesJRPCRequest =
  JRPCRequest<StoreKeySharesJRPCRequestParams>;

export type StoreKeySharesJRPCResponse = JRPCResponse<null>;
