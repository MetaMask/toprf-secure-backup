export type JWTVerificationParams = {
  // for now we only support one idToken, in future we will support multiple to remove commitment call
  // so leaving it as an array for future use
  idTokens: string[];
  endpoints: string[];
  indexes: number[];
  verifier: string;
};

export type AuthToken = {
  token: string;
  nodeIndex: number;
};

export type JWTVerificationResult = {
  authTokens: AuthToken[];
  existingSharePublicData?: {
    pubKeyX: string;
    pubKeyY: string;
    shareIndex: number;
  };
  isExistingUser: boolean;
};

export type RegisterNewSecretParams = {
  authTokens: AuthToken[];
  secretData: string;
};

export type RegisterNewSecretResult = {
  encKey: string;
};

export type FetchSecretDataParams = {
  authTokens: AuthToken[];
  password: string;
};

export type FetchSecretDataResult = {
  encKey: string;
  secretData: string;
};
export type UpdateEncKeyParams = {
  authTokens: AuthToken[];
  newPassword: string;
} & (
  | { encKey: string; oldPassword?: never }
  | { encKey?: never; oldPassword: string }
);

export type UpdateEncKeyResult = {
  encKey: string;
};

export type UpdateSecretDataParams = {
  authTokens: AuthToken[];
  encKey: string;
  newSecretData: string;
};

export type UpdateSecretDataResult = {
  encKey: string;
};

export type MetamaskTOPRFAuth = {
  verifyIdToken: (
    params: JWTVerificationParams,
  ) => Promise<JWTVerificationResult>;
  registerNewSecret: (
    params: RegisterNewSecretParams,
  ) => Promise<RegisterNewSecretResult>;
  fetchSecretData: (
    params: FetchSecretDataParams,
  ) => Promise<FetchSecretDataResult>;
  updateEncKey: (params: UpdateEncKeyParams) => Promise<UpdateEncKeyResult>;
  updateSecretData: (
    params: UpdateSecretDataParams,
  ) => Promise<UpdateSecretDataResult>;
};
