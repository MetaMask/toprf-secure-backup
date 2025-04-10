import { JsonRpcVersion, TOPRFError } from '@metamask/auth-network-utils';
import { getPubKey, validatePubKey } from './getPubKeyRequest';

describe('getPubKey', () => {
  it('should fail with insufficient auth tokens', async function () {
    await expect(
      getPubKey({
        authTokens: [],
        nodeEndpointsMap: {},
        verifier: 'torus-test-health',
        verifierId: 'dummy-id',
      }),
    ).rejects.toThrow(
      TOPRFError.insufficientAuthTokens(`At least 3 auth tokens are required.`),
    );
  });

  it('should fail on inconsistent pub key responses', async function () {
    const resultArr = [
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: { pubKey: '1234' },
      },
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: { pubKey: '1234' },
      },
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: { pubKey: '5678' },
      },
      {
        id: 1,
        jsonrpc: '2.0' as JsonRpcVersion,
        result: { pubKey: '5678' },
      },
    ];

    await expect(validatePubKey(resultArr)).rejects.toThrow(
      TOPRFError.couldNotDeriveThresholdAuthPubKey(),
    );
  });
});
