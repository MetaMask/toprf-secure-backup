import type { JRPCResponse, JRPCRequest } from '@metamask/auth-network-utils';

import type { KeyChangeProof } from './interfaces';

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

export type BaseShareImportItem = {
  encryptedAuthToken: string;
  encryptedShare: string;
  shareKeyIndex: number;
  nodeIndex: number;
  sssEndpoint: string;
};

export type NewUserShareImportItem = BaseShareImportItem;

export type KeyChangeShareImportItem = BaseShareImportItem & KeyChangeProof;

export type ShareImportItem<
  ShareType extends 'standard' | 'keyChange' = 'standard',
> = ShareType extends 'standard'
  ? NewUserShareImportItem
  : KeyChangeShareImportItem;

export type StoreKeySharesJRPCRequestParams = {
  verifier: string;
  verifierId: string;
  pubKey: string;
  shareImportItems: ShareImportItem[];
};

export type StoreKeySharesJRPCRequest =
  JRPCRequest<StoreKeySharesJRPCRequestParams>;

export type StoreKeySharesJRPCResponse = JRPCResponse<null>;

export type ResetRateLimitJRPCRequestParams = {
  authToken: string;
  signature: string;
  signedData: string;
  verifier: string;
  verifierId: string;
};

export type ResetRateLimitJRPCRequest =
  JRPCRequest<ResetRateLimitJRPCRequestParams>;

export type ResetRateLimitJRPCResponse = JRPCResponse<boolean>;

export type ToprfEvalJRPCRequestParams = {
  authToken: string;
  shareCoefficient: string;
  blindedInputX: string;
  blindedInputY: string;
  verifier: string;
  verifierId: string;
};

export type ToprfEvalJRPCRequest = JRPCRequest<ToprfEvalJRPCRequestParams>;

export type ToprfEvalResult = {
  blindedOutputX: string;
  blindedOutputY: string;
  nodeIndex: number;
  pubKey: string;
};

export type ToprfEvalJRPCResponse = JRPCResponse<ToprfEvalResult>;
