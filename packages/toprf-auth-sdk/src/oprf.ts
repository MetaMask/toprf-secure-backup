// Disabling `id-length` because `F(k, x)` is common terminology in the context
// of PRFs.
/* eslint-disable id-length */

// TODO: add docs
/* eslint-disable jsdoc/require-jsdoc */

import { Field } from '@noble/curves/abstract/modular';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { secp256k1, hashToCurve } from '@noble/curves/secp256k1';

/**
 * Generates a random scalar value using the secp256k1 curve.
 *
 * @returns A random scalar value as a bigint.
 */
function generateRandomScalar(): bigint {
  return bytesToNumberBE(secp256k1.utils.randomPrivateKey());
}

const scalarField = Field(secp256k1.CURVE.n);

export class OPRF {
  public static blind(x: Uint8Array): { a: ProjPointType<bigint>; r: bigint } {
    const r = generateRandomScalar();
    const a = hashToCurve(x).multiply(r);
    const aProjective = secp256k1.ProjectivePoint.fromAffine(a.toAffine());
    return { a: aProjective, r };
  }

  public static blindEval(
    k: bigint,
    a: ProjPointType<bigint>,
  ): ProjPointType<bigint> {
    const b = a.multiply(k);
    return b;
  }

  public static unblindAndHash(
    x: Uint8Array,
    b: ProjPointType<bigint>,
    r: bigint,
  ): Uint8Array {
    const rInv = scalarField.inv(r);
    const d = b.multiply(rInv);
    const y = secp256k1.CURVE.hash(new Uint8Array([...x, ...d.toRawBytes()]));

    return y;
  }

  public static localEval(k: bigint, x: Uint8Array): Uint8Array {
    // Blind input.
    const { a, r } = this.blind(x);
    // Compute blinded output.
    const b = a.multiply(k);
    // Unblind output.
    return this.unblindAndHash(x, b, r);
  }
}
