import { KEY_TYPE } from "@toruslabs/constants";
import { Ecies } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { curve } from "elliptic";

export type BNString = string | BN;

export type StringifiedType = Record<string, unknown>;

export type KeyType = (typeof KEY_TYPE)[keyof typeof KEY_TYPE];

export type v2NonceResultType = {
  typeOfUser: "v2";
  nonce?: string;
  seed?: string;
  pubNonce: { x: string; y: string };
  ipfs?: string;
  upgraded: boolean;
};

export type v1NonceResultType = { typeOfUser: "v1"; nonce?: string; seed?: string };

export type GetOrSetNonceResult = v2NonceResultType | v1NonceResultType;

export type EciesHex = {
  [key in keyof Ecies]: string;
} & { mode?: string };

export interface PrivateKeyData {
  oAuthKeyScalar: BN;
  oAuthPubX: BN;
  oAuthPubY: BN;
  SigningPubX: BN;
  SigningPubY: BN;
  metadataNonce: BN;
  metadataSigningKey: BN;
  finalUserPubKeyPoint: curve.base.BasePoint;
  encryptedSeed?: string;
}

export interface EncryptedSeed {
  enc_text: string;
  public_key?: string;
  metadata: EciesHex;
}

export interface CommitmentRequestResult {
  signature: string;
  data: string;
  nodepubx: string;
  nodepuby: string;
  nodeindex: string;
  pub_key_x: string;
}

export interface ImportedShare {
  oauth_pub_key_x: string;
  oauth_pub_key_y: string;
  final_user_point: curve.base.BasePoint;
  signing_pub_key_x: string;
  signing_pub_key_y: string;
  encrypted_share: string;
  encrypted_share_metadata: EciesHex;
  encrypted_seed?: string;
  node_index: number;
  key_type: string;
  nonce_data: string;
  nonce_signature: string;
}

export interface SetNonceData {
  operation: string;
  data: string;
  seed?: string;
  timestamp: string;
}

export interface GetORSetKeyResponse {
  keys: {
    pub_key_X: string;
    pub_key_Y: string;
    address: string;
    nonce_data?: GetOrSetNonceResult;
    created_at?: number;
  }[];
  is_new_key: boolean;
  node_index: string;
  server_time_offset?: string;
}

export interface VerifierLookupResponse {
  keys: {
    pub_key_X: string;
    pub_key_Y: string;
    signing_pub_key_X?: string;
    signing_pub_key_Y?: string;
    address: string;
  }[];
  server_time_offset?: string;
}


export type MetadataOperation = "getNonce" | "getOrSetNonce";

export interface MetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  key_type?: KeyType;
  set_data: {
    data: "getNonce" | "getOrSetNonce" | string;
    timestamp: string;
  };
  signature: string;
}

export interface NonceMetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  set_data: Partial<SetNonceData>;
  signature: string;
  key_type?: KeyType;
  seed?: string;
}

export interface SapphireMetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  key_type: "secp256k1" | "ed25519";
  set_data: {
    operation: "getNonce" | "getOrSetNonce" | string;
    timestamp?: string;
  };
  signature?: string;
}