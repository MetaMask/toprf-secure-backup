import type { Algorithm as JwtAlgorithm } from "jsonwebtoken";
/**
 * Generates the id token for the given verifier id and algorithm.
 *
 * @param verifierId - The verifier id of the user.
 * @param alg - The algorithm.
 *
 * @returns The id token.
 */
export declare const generateIdToken: (verifierId: string, alg: JwtAlgorithm) => string;
//# sourceMappingURL=testHelpers.d.cts.map