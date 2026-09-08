import { post } from '@toruslabs/http-helpers';

import { WEB3_CLIENT_HEADER } from './constants';
import { getSssJrpcRequestHeaders, postJRPCRequest } from './utils';

jest.mock('@toruslabs/http-helpers', () => ({
  post: jest.fn(),
}));

const mockPost = post as jest.MockedFunction<typeof post>;

const request = {
  id: 10,
  jsonrpc: '2.0' as const,
  method: 'TOPRFCommitmentRequest',
  params: { tokenCommitment: 'abc' },
};

describe('getSssJrpcRequestHeaders', () => {
  it('returns empty request init when clientIdentifier is omitted', () => {
    expect(getSssJrpcRequestHeaders()).toStrictEqual({});
  });

  it('returns empty request init when clientIdentifier is empty', () => {
    expect(getSssJrpcRequestHeaders('')).toStrictEqual({});
  });

  it('sets only x-web3-client when clientIdentifier is provided', () => {
    expect(
      getSssJrpcRequestHeaders('metamask-extension@13.46.1'),
    ).toStrictEqual({
      headers: {
        [WEB3_CLIENT_HEADER]: 'metamask-extension@13.46.1',
      },
    });
  });
});

describe('postJRPCRequest', () => {
  const endpoint = 'https://node-1.example/sss/jrpc';

  beforeEach(() => {
    mockPost.mockResolvedValue({
      id: 10,
      jsonrpc: '2.0',
      result: { node_index: 1 },
    });
  });

  it('does not send x-web3-client when clientIdentifier is omitted', async () => {
    await postJRPCRequest(endpoint, request);

    expect(mockPost).toHaveBeenCalledWith(
      endpoint,
      expect.objectContaining({
        method: request.method,
      }),
      {},
      { logTracingHeader: false },
    );
    const body = mockPost.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('client');
    expect(body).not.toHaveProperty('clientIdentifier');
    expect(JSON.stringify(body)).not.toContain(WEB3_CLIENT_HEADER);
  });

  it('does not send x-web3-client when clientIdentifier is empty', async () => {
    await postJRPCRequest(endpoint, request, '');

    expect(mockPost.mock.calls[0][2]).toStrictEqual({});
  });

  it('sends x-web3-client as a header and not in the JSON-RPC body', async () => {
    const clientIdentifier = 'metamask-extension@13.46.1';
    await postJRPCRequest(endpoint, request, clientIdentifier);

    expect(mockPost).toHaveBeenCalledWith(
      endpoint,
      expect.objectContaining({
        method: request.method,
        params: expect.objectContaining({
          token_commitment: 'abc',
        }),
      }),
      {
        headers: {
          [WEB3_CLIENT_HEADER]: clientIdentifier,
        },
      },
      { logTracingHeader: false },
    );
    const body = mockPost.mock.calls[0][1] as Record<string, unknown>;
    expect(body).not.toHaveProperty('client');
    expect(body).not.toHaveProperty('clientIdentifier');
    expect(JSON.stringify(body)).not.toContain(clientIdentifier);
    expect(JSON.stringify(mockPost.mock.calls[0][2])).not.toContain(
      'x-web3-client-version',
    );
  });
});
