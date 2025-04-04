"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateIdToken = void 0;
const jsonwebtoken_1 = require("jsonwebtoken");
const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;
/**
 * Generates the id token for the given verifier id and algorithm.
 *
 * @param verifierId - The verifier id of the user.
 * @param alg - The algorithm.
 *
 * @returns The id token.
 */
const generateIdToken = (verifierId, alg) => {
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
    return (0, jsonwebtoken_1.sign)(payload, jwtPrivateKey, algo);
};
exports.generateIdToken = generateIdToken;
//# sourceMappingURL=testHelpers.cjs.map