import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';

const AUTH_TOKEN_EXPIRY = 1800000000;
// TODO: Replace with the dynamic values
// Test Private key to be used for generating the auth token
const TEST_PRIVATE_KEY =
  '89b0423c215f52898569ffecaaffc388beb07d2fbae3dd008645d8b34c7bb21f';
// Test audience to be used for generating the auth token
const TEST_AUD =
  '10d28038e840829e87d9ae0049c7382fdcc14c749f2abb7b0f01141966d6c421';

// generate Mock Auth Token for metadata requests
/**
 *
 * @param params - params required to generate the test auth token
 * @param params.verifier - verifier address
 * @param params.verifierId - verifier id
 * @returns base-64 encoded auth token
 */
export function generateMockAuthTokenForMetadataRequests(params: {
  verifier: string;
  verifierId: string;
}): string {
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
  const signature = signatureObject.toCompactHex();

  const authSig = {
    ...authNetworkTokenWithoutSig,
    signature,
  };

  // base-64 encode the authSig object (with signature)
  const b64EncodedAuthSig = Buffer.from(JSON.stringify(authSig)).toString(
    'base64',
  );

  return b64EncodedAuthSig;
}
