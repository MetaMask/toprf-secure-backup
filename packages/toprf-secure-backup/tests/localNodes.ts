import { NodeDetailManager } from '@toruslabs/fetch-node-details';

/*
 * Test-only routing for the local SSS dev nodes (sss-service docker-compose.local.yml, ports 5001-5005).
 *
 * Only the e2e suite calls routeToLocalNodes(); unit tests are not affected.
 *
 * TOPRF_TEST_LOCAL_NODES=true: every FND lookup returns the local nodes instead of devnet.
 * Node public keys match NODE_PUB_KEYS_X / NODE_PUB_KEYS_Y in sss-service .env.local.
 *
 * TOPRF_TEST_METADATA_URL=<url>: metadata requests the SDK sends to a local node
 * (http://localhost:500N/metadata/...) are sent to this URL instead, because the
 * local sss-service does not serve /metadata.
 */
const LOCAL_NODE_PUB_KEYS_X = [
  'a560f5a728c3d6557ae15d8b4348025df041c4809ea46ed52b5e1a779eeaf803',
  '57dc73d3400ef025e9b97328a175b92709b2d3891d57848dec0d81f9df3cd1b0',
  '62fb01bafc2cd1315b89c996fdd52d4bbf24e4cec9de0e28242ad0ccb5d19222',
  'c79564e86cf3605d27cf571f1fe80b5c99aca82cd55063c7882b28f692900104',
  'b0a07ea89edf67cda0cf8d38492c141f46f7027b4646bc55ac3a682ad2a33c3f',
];

const LOCAL_NODE_PUB_KEYS_Y = [
  'b8a546880e9cb686ed230e6f1a08439be2e1fb1f4c7b62b3eb65b3d2b374d383',
  '54fc57b4a663a6336eb02f03251023b64576023c6fba20d0fdebd2b55dc3865f',
  'b1487bab2f2e3e0eccb83f6bdef0ca3c41f7bf7506a4be49207883f72bd4f774',
  'f2bfa9078d647c4a42edfaff9fae08b33fa5fe0ee31a603272d4277718ca8627',
  '730c3fbd2abc8dbd51b718d3d14f9fb5dac19919b0f7fb70810fb23c453c6291',
];

const LOCAL_NODE_PORTS = [5001, 5002, 5003, 5004, 5005];

/**
 * Rewrites a local node metadata URL to the configured metadata URL.
 *
 * @param url - The request URL.
 * @param metadataUrl - The metadata service base URL.
 * @returns The URL to request.
 */
const rewriteMetadataUrl = (url: string, metadataUrl: string): string => {
  const index = url.indexOf('/metadata/');
  if (url.startsWith('http://localhost:') && index !== -1) {
    return `${metadataUrl}${url.slice(index + '/metadata'.length)}`;
  }
  return url;
};

/**
 * Whether the e2e suite should route to the local nodes (TOPRF_TEST_LOCAL_NODES=true).
 *
 * @returns True when local node routing is enabled.
 */
export const isLocalNodesEnabled = (): boolean =>
  // eslint-disable-next-line n/no-process-env
  process.env.TOPRF_TEST_LOCAL_NODES === 'true';

/**
 * Routes FND lookups and metadata requests to the local nodes for the calling suite.
 * Call from inside a describe block. Restores the originals after each test.
 */
export function routeToLocalNodes(): void {
  // eslint-disable-next-line n/no-process-env
  const metadataUrl = process.env.TOPRF_TEST_METADATA_URL;
  let savedFetch: typeof fetch | undefined;

  // eslint-disable-next-line jest/require-top-level-describe
  beforeEach(() => {
    jest
      .spyOn(NodeDetailManager.prototype, 'getNodeDetails')
      .mockResolvedValue({
        torusNodeSSSEndpoints: LOCAL_NODE_PORTS.map(
          (port) => `http://localhost:${port}/jrpc`,
        ),
        torusIndexes: LOCAL_NODE_PORTS.map((_, i) => i + 1),
        torusNodePub: LOCAL_NODE_PUB_KEYS_X.map((pubKeyX, i) => ({
          X: pubKeyX,
          Y: LOCAL_NODE_PUB_KEYS_Y[i],
        })),
      } as never);

    if (metadataUrl) {
      // Assigned directly rather than with jest.spyOn: a test that spies on fetch
      // would otherwise wrap this same spy and recurse into it.
      const originalFetch = global.fetch;
      savedFetch = originalFetch;
      global.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
        let url: string;
        if (typeof input === 'string') {
          url = input;
        } else if (input instanceof URL) {
          url = input.href;
        } else {
          url = input.url;
        }
        return originalFetch(
          rewriteMetadataUrl(url, metadataUrl),
          init,
        ) as never;
      }) as typeof fetch;
    }
  });

  // eslint-disable-next-line jest/require-top-level-describe
  afterEach(() => {
    // restoreMocks does not undo a direct assignment, so restore fetch here.
    if (savedFetch) {
      global.fetch = savedFetch;
    }
  });
}
