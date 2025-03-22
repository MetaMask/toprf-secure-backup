import type { Ecies } from '@toruslabs/eccrypto';
import type BN from 'bn.js';

export type BNString = string | BN;

export type StringifiedType = Record<string, unknown>;

export type EciesHex = {
  [key in keyof Ecies]: string;
} & { mode?: string };

export type JRPCResponse<T> = {
  id: number;
  jsonrpc: '2.0';
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
};

export type JRPCRequest<T> = {
  jsonrpc: '2.0';
  method: string;
  id: number;
  params: T;
};
