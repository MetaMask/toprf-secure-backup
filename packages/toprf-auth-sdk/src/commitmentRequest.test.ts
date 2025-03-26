import { getSecp256K1Curve } from '@metamask/auth-network-utils';
import { randomBytes } from 'crypto';
import { keccak256 } from 'ethereum-cryptography/keccak';

import {
  createCommitmentRequestParams,
  createCommitmentRequest,
} from './commitmentRequest';
import type { CommitmentRequestResult } from './jrpcInterfaces';
import { getRandomNode } from './utils';

describe('commitment request', function () {
  it('should create a commitment request', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();

    const { url: endpoint, index } = getRandomNode();
    const tokenCommitment = randomBytes(16).toString('hex');
    const verifier = 'google';
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
  });
});
