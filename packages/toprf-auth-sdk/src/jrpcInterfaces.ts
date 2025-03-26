import type {
  JRPCResponse,
  JRPCRequest,
  EciesHex,
} from '@metamask/auth-network-utils';

export type CommitmentJRPCRequestParams = {
  messagePrefix: string;
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

export type CommitmentJRPCResponse = JRPCResponse<CommitmentRequestResult>;

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
  pubKey: string;
  keyIndex: number;
};

export type AuthJRPCResponse = JRPCResponse<AuthRequestResult>;

export type ShareImportItem = {
  encryptedShare: string;
  encryptedShareMetadata: EciesHex;
  shareKeyIndex: number;
  nodeIndex: number;
  sssEndpoint: string;
};

export type StoreKeySharesJRPCRequestParams = {
  verifier: string;
  verifierId: string;
  authToken: string;
  pubKey: string;
  shareImportItems: ShareImportItem[];
};

export type StoreKeySharesJRPCRequest =
  JRPCRequest<StoreKeySharesJRPCRequestParams>;

export type StoreKeySharesJRPCResponse = JRPCResponse<null>;
