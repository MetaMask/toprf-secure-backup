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

    const { url, index } = getRandomNode();
    const endpoint = `${url}/sss/jrpc`;

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
    const result = await createCommitmentRequest(endpoint, params);

    expect(result).toBeDefined();
    expect(result.jsonrpc).toBe('2.0');
    expect(result.id).toBeDefined();
    expect(result.result).toBeDefined();

    const response = result.result as CommitmentRequestResult;

    expect(response.signature).toBeDefined();
    expect(response.data).toBeDefined();
    expect(response.node_pub_x).toBeDefined();
    expect(response.node_pub_y).toBeDefined();
    expect(response.node_index).toBe(index);

    // Rebuild the public key from the node's pub key coordinates
    const nodePubKey = curve.keyFromPublic(
      { x: response.node_pub_x, y: response.node_pub_y },
      'hex',
    );

    // Compute the Keccak‑256 hash of the data
    const dataBuffer = Buffer.from(response.data);
    const msgHashBuffer = Buffer.from(keccak256(dataBuffer));

    // Extract r and s from the signature (discarding the extra recovery byte)
    const sigHex = response.signature;
    const signature = {
      r: sigHex.slice(0, 64),
      s: sigHex.slice(64, 128),
    };

    // Verify the signature against the Keccak‑256 hash
    expect(nodePubKey.verify(msgHashBuffer, signature)).toBe(true);
  });
});
