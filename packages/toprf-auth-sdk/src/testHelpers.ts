import type { Algorithm as JwtAlgorithm } from 'jsonwebtoken';
import { sign } from 'jsonwebtoken';

const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;
export const generateIdToken = (email: string, alg: JwtAlgorithm): string => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'torus-key-test',
    aud: 'torus-key-test',
    name: email,
    email,
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
