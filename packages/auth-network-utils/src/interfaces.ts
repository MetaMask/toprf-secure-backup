import type { Ecies } from '@toruslabs/eccrypto';
import type BN from 'bn.js';

export type BNString = string | BN;

export type StringifiedType = Record<string, unknown>;

export type EciesHex = {
  [key in keyof Ecies]: string;
} & { mode?: string };
