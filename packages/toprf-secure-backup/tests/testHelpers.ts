import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { sign } from 'jsonwebtoken';
import type { Algorithm as JwtAlgorithm } from 'jsonwebtoken';

import type { NodeAuthTokens } from '../src/interfaces';

const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;

const AUTH_TOKEN_EXPIRY = 1800000000;
// TODO: Replace with the dynamic values
// Test Private key to be used for generating the auth token
const TEST_PRIVATE_KEY =
  '89b0423c215f52898569ffecaaffc388beb07d2fbae3dd008645d8b34c7bb21f';
// Test audience to be used for generating the auth token
const TEST_AUD =
  '10d28038e840829e87d9ae0049c7382fdcc14c749f2abb7b0f01141966d6c421';

/**
 * Generates the id token for the given verifier id and algorithm.
 *
 * @param verifierId - The verifier id of the user.
 * @param alg - The algorithm.
 *
 * @returns The id token.
 */
export const generateIdToken = (
  verifierId: string,
  alg: JwtAlgorithm,
): string => {
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

/**
 * Generates the mock auth token for the given verifier and verifier id.
 *
 * @param params - params required to generate the test auth token
 * @param params.verifier - verifier address
 * @param params.verifierId - verifier id
 * @returns NodeAuthTokens
 */
export function generateMockAuthTokenForMetadataRequests(params: {
  verifier: string;
  verifierId: string;
}): NodeAuthTokens {
  const { verifier, verifierId } = params;

  const authNetworkTokenWithoutSig = {
    verifier,
    verifier_id: verifierId,
    aud: TEST_AUD,
    scope: 'email',
    temp_key_x: '0x123',
    temp_key_y: '0x456',
    exp: AUTH_TOKEN_EXPIRY,
  };

  // base-64 encode the authNetworkToken object (without signature)
  const message = Buffer.from(
    JSON.stringify(authNetworkTokenWithoutSig),
  ).toString('base64');
  const messageHash = keccak256(message);

  // sign the msg
  const signatureObject = secp256k1.sign(messageHash, TEST_PRIVATE_KEY);
  const nodePubKeyRaw = secp256k1.getPublicKey(TEST_PRIVATE_KEY);
  const nodePubKey = bytesToHex(nodePubKeyRaw);
  const signature = signatureObject.toCompactHex();

  const authSig = {
    ...authNetworkTokenWithoutSig,
    signature,
  };

  // base-64 encode the authSig object (with signature)
  const b64EncodedAuthSig = Buffer.from(JSON.stringify(authSig)).toString(
    'base64',
  );

  const nodeAuthTokens: NodeAuthTokens = [
    {
      authToken: b64EncodedAuthSig,
      nodeIndex: 1,
      nodePubKey,
    },
    {
      authToken: b64EncodedAuthSig,
      nodeIndex: 2,
      nodePubKey,
    },
    {
      authToken: b64EncodedAuthSig,
      nodeIndex: 3,
      nodePubKey,
    },
  ];

  return nodeAuthTokens;
}
