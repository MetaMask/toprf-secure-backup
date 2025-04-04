// Disabling `id-length` because `F(k, x)` is common terminology in the context
// of PRFs.
/* eslint-disable id-length */
import { Field } from "@noble/curves/abstract/modular";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";
import { secp256k1, hashToCurve } from "@noble/curves/secp256k1";
/**
 * Generates a random scalar value using the secp256k1 curve.
 *
 * @returns A random scalar value as a bigint.
 */
export function generateRandomScalar() {
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
    static blind(x) {
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
    static blindEval(k, a) {
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
     * @returns The unblinded output as a `Uint8Array`.
     */
    static unblindAndHash(x, b, r) {
        const rInv = scalarField.inv(r);
        const d = b.multiply(rInv);
        const y = secp256k1.CURVE.hash(new Uint8Array([...x, ...d.toRawBytes()]));
        return y;
    }
    /**
     * Performs local evaluation of the OPRF using a given key and input value.
     *
     * @param k - The OPRF key.
     * @param x - The input value as a `Uint8Array` to be evaluated.
     * @returns The evaluated output as a `Uint8Array`.
     */
    static localEval(k, x) {
        // Blind input.
        const { a, r } = this.blind(x);
        // Compute blinded output.
        const b = a.multiply(k);
        // Unblind output.
        return this.unblindAndHash(x, b, r);
    }
}
//# sourceMappingURL=oprf.mjs.map