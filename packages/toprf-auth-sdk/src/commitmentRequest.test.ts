import { getSecp256K1Curve } from '@metamask/auth-network-utils';
import { randomBytes } from 'crypto';
import { keccak256 } from 'ethereum-cryptography/keccak';

import { commitIdToken } from './commitmentRequest';
import { NODE_URLS } from './constants';

describe('commitment request', function () {
  it('should commit idToken and validate responses', async function () {
    const curve = getSecp256K1Curve();
    const keyPair = curve.genKeyPair();
    const pubPoint = keyPair.getPublic();
    const sessionPubKeyX = pubPoint.getX().toString('hex');
    const sessionPubKeyY = pubPoint.getY().toString('hex');

    const endpoints = NODE_URLS;
    const idToken = randomBytes(16).toString('hex');
    const verifier = 'google';

    const resultArr = await commitIdToken({
      idToken,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
      endpoints,
    });

    expect(resultArr).toBeDefined();
    expect(resultArr.length).toBeGreaterThanOrEqual(
      Math.floor((endpoints.length * 3) / 4) + 1,
    );

    resultArr.forEach((result) => {
      expect(result.signature).toBeDefined();
      expect(result.data).toBeDefined();
      expect(result.nodePubX).toBeDefined();
      expect(result.nodePubY).toBeDefined();

      const nodePubKey = curve.keyFromPublic(
        { x: result.nodePubX, y: result.nodePubY },
        'hex',
      );

      const dataBuffer = Buffer.from(result.data);
      const msgHashBuffer = Buffer.from(keccak256(dataBuffer));

      const sigHex = result.signature;
      const signature = {
        r: sigHex.slice(0, 64),
        s: sigHex.slice(64, 128),
      };

      expect(nodePubKey.verify(msgHashBuffer, signature)).toBe(true);
    });
  });
});
