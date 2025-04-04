import $jsonwebtoken from "jsonwebtoken";
const { sign } = $jsonwebtoken;
const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;
/**
 * Generates the id token for the given verifier id and algorithm.
 *
 * @param verifierId - The verifier id of the user.
 * @param alg - The algorithm.
 *
 * @returns The id token.
 */
export const generateIdToken = (verifierId, alg) => {
    const iat = Math.floor(Date.now() / 1000);
    const payload = {
        iss: 'torus-key-test',
        aud: 'torus-key-test',
        name: verifierId,
        email: verifierId,
        scope: 'email',
        iat,
        eat: iat + 120,
    };
    const algo = {
        expiresIn: 120,
        algorithm: alg,
    };
    return sign(payload, jwtPrivateKey, algo);
};
//# sourceMappingURL=testHelpers.mjs.map