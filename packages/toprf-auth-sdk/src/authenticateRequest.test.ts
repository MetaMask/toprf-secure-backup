import {
  getSecp256K1Curve,
  keccak256AndHexify,
} from '@metamask/auth-network-utils';
import { keccak256 } from 'ethereum-cryptography/keccak';

import {
  createAuthenticateRequest,
  createAuthenticateRequestParams,
} from './authenticateRequest';
import {
  createCommitmentRequestParams,
  createCommitmentRequest,
} from './commitmentRequest';
import type { CommitmentRequestResult } from './jrpcInterfaces';
import { generateIdToken } from './testHelpers';
import { getRandomNode } from './utils';

describe('authenticate request', function () {
  it('should create a authenticate request', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();

    const { url, index } = getRandomNode();
    const endpoint = `${url}/sss/jrpc`;
    const verifier = 'torus-test-health';
    const verifierID = 'test-verifier-id';
    const idToken = generateIdToken(verifierID, 'ES256');
    const tokenCommitment = keccak256AndHexify(Buffer.from(idToken, 'utf-8'));
    const sessionPubKeyX = pubPoint.getX().toString('hex');
    const sessionPubKeyY = pubPoint.getY().toString('hex');

    const params = createCommitmentRequestParams(
      tokenCommitment,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
    );
    const jrpcResponse = await createCommitmentRequest(endpoint, params);
    expect(jrpcResponse).toBeDefined();
    expect(jrpcResponse.jsonrpc).toBe('2.0');
    expect(jrpcResponse.id).toBeDefined();
    expect(jrpcResponse.result).toBeDefined();

    const result = jrpcResponse.result as CommitmentRequestResult;

    expect(result.signature).toBeDefined();
    expect(result.data).toBeDefined();
    expect(result.nodePubX).toBeDefined();
    expect(result.nodePubY).toBeDefined();
    expect(result.nodeIndex).toBe(index);

    // Rebuild the public key from the node's pub key coordinates
    const nodePubKey = curve.keyFromPublic(
      { x: result.nodePubX, y: result.nodePubY },
      'hex',
    );

    // Compute the Keccak‑256 hash of the data
    const dataBuffer = Buffer.from(result.data);
    const msgHashBuffer = Buffer.from(keccak256(dataBuffer));

    // Extract r and s from the signature (discarding the extra recovery byte)
    const sigHex = result.signature;
    const signature = {
      r: sigHex.slice(0, 64),
      s: sigHex.slice(64, 128),
    };

    // Verify the signature against the Keccak‑256 hash
    expect(nodePubKey.verify(msgHashBuffer, signature)).toBe(true);

    const authParams = createAuthenticateRequestParams(
      idToken,
      verifier,
      verifierID,
      [result],
    );

    const authJRPCRequest = await createAuthenticateRequest(
      endpoint,
      authParams,
    );
    console.log(authJRPCRequest);
    expect(authJRPCRequest).toBeDefined();
    expect(authJRPCRequest.jsonrpc).toBe('2.0');
    expect(authJRPCRequest.id).toBeDefined();
    expect(authJRPCRequest.result).toBeDefined();
  });
});
