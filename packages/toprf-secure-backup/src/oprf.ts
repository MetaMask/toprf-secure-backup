// Disabling `id-length` because `F(k, x)` is common terminology in the context
// of PRFs.
/* eslint-disable id-length */

import { Field } from '@noble/curves/abstract/modular';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1, hashToCurve } from '@noble/curves/secp256k1';

export type KeyDeriver = {
  deriveKey(seed: Uint8Array, salt: Uint8Array): Promise<Uint8Array>;
};

export type FetchMetadataAccessCreds = () => Promise<
  | { accessToken: string; apiKey?: string }
  | { accessToken?: string; apiKey: string }
>;

/**
 * Generates a random scalar value using the secp256k1 curve.
 *
 * @returns A random scalar value as a bigint.
 */
export function generateRandomScalar(): bigint {
  return bytesToNumberBE(secp256k1.utils.randomPrivateKey());
}

const scalarField = Field(secp256k1.CURVE.n);

/**
 * (Threshold) OPRF (Oblivious Pseudorandom Function) class. Implements the
 * 2HashDH OPRF from https://eprint.iacr.org/2016/144.pdf,
 * https://eprint.iacr.org/2017/363.pdf.
 */
export class OPRF {
  /**
   * Blinds an input value by hashing it to an elliptic curve point and
   * multiplying it by a random scalar. This process is used in cryptographic
   * protocols to obscure the input value while preserving its structure.
   *
   * @param x - The input value as a `Uint8Array` to be blinded.
   * @returns An object containing:
   * - `a`: The blinded elliptic curve point as a projective point.
   * - `r`: The random scalar used for blinding.
   */
  public static blind(x: Uint8Array): { a: ProjPointType<bigint>; r: bigint } {
    const r = generateRandomScalar();
    const a = hashToCurve(x).multiply(r);
    const aProjective = secp256k1.ProjectivePoint.fromAffine(a.toAffine());
    return { a: aProjective, r };
  }

  /**
   * Evaluates the blinded input by multiplying the elliptic curve point by a
   * scalar.
   *
   * @param k - The OPRF key, or key share.
   * @param a - The blinded elliptic curve point as a projective point.
   * @returns The blinded output as a projective point.
   */
  public static blindEval(
    k: bigint,
    a: ProjPointType<bigint>,
  ): ProjPointType<bigint> {
    const b = a.multiply(k);
    return b;
  }

  /**
   * Unblinds the output of the OPRF by multiplying the blinded output with the
   * inverse of the blinding scalar and hashing it with the original input.
   *
   * @param x - The original input value as a `Uint8Array`.
   * @param b - The blinded output as a projective point.
   * @param r - The blinding scalar used for blinding.
   * @param keyDeriver - An optional key derivation function.
   * @returns The unblinded output as a `Uint8Array`.
   */
  public static async unblindAndHash(
    x: Uint8Array,
    b: ProjPointType<bigint>,
    r: bigint,
    keyDeriver?: KeyDeriver,
  ): Promise<Uint8Array> {
    const rInv = scalarField.inv(r);
    const d = b.multiply(rInv);
    let y = secp256k1.CURVE.hash(new Uint8Array([...x, ...d.toRawBytes()]));

    // Optionally, inject another key derivation step. This can be used for
    // slowing down the key derivation to increase resistance against local
    // brute force attacks.
    if (keyDeriver) {
      const l = y.length;
      y = await keyDeriver.deriveKey(y.slice(0, l / 2), y.slice(l / 2));
    }

    return y;
  }

  /**
   * Performs local evaluation of the OPRF using a given key and input value.
   *
   * @param k - The OPRF key.
   * @param x - The input value as a `Uint8Array` to be evaluated.
   * @param keyDeriver - An optional key derivation function.
   * @returns The evaluated output as a `Uint8Array`.
   */
  public static async localEval(
    k: bigint,
    x: Uint8Array,
    keyDeriver?: KeyDeriver,
  ): Promise<Uint8Array> {
    // Blind input.
    const { a, r } = this.blind(x);
    // Compute blinded output.
    const b = a.multiply(k);
    // Unblind output.
    return this.unblindAndHash(x, b, r, keyDeriver);
  }
}
