import {
  createCommitmentRequestParams,
  createCommitmentRequest,
} from './commitmentRequest';

describe('commitment request', function () {
  // define the test cases for the commitment request file
  it('should create a commitment request', function () {
    const tokenCommitment = '0x1234567890abcdef';
    const verifier = '0x1234567890abcdef';
    const sessionPubKeyX = '0x1234567890abcdef';
    const sessionPubKeyY = '0x1234567890abcdef';
    const endpoint = 'https://example.com';
    const params = createCommitmentRequestParams(
      tokenCommitment,
      verifier,
      sessionPubKeyX,
      sessionPubKeyY,
    );
    const result = createCommitmentRequest(endpoint, params);
    expect(result).toBeDefined();
  });
});
