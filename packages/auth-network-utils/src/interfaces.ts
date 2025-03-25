import type { Ecies } from '@toruslabs/eccrypto';
import type BN from 'bn.js';

export type BnString = string | BN;

export type StringifiedType = Record<string, unknown>;

export type EciesHex = {
  [key in keyof Ecies]: string;
} & { mode?: string };

export type JsonRpcResponse<T> = {
  id: number;
  jsonrpc: '2.0';
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
};

export type JsonRpcRequest<T> = {
  jsonrpc: '2.0';
  method: string;
  id: number;
  params: T;
};
