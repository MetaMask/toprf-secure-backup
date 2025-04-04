/**
 * Deterministically derives an secp256k1 keypair intended for authentication.
 *
 * @param seed The input seed from which the output key is derived from.
 * @returns The derived keypair.
 */
export declare function deriveAuthenticationKeyPair(seed: Uint8Array): {
    sk: bigint;
    pk: Uint8Array;
};
/**
 * Deterministically derives an AES-256 key intended for data encryption.
 *
 * @param seed The input seed from which the output key is derived from.
 * @returns The derived key.
 */
export declare function deriveEncryptionKey(seed: Uint8Array): Uint8Array;
//# sourceMappingURL=keyDerivation.d.mts.map