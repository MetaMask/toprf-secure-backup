import { toChecksumAddress } from './cryptoUtils';

describe('keys utils', function () {
  it('should be able to convert to EIP-55 `checksum` address', function () {
    const address = toChecksumAddress(
      '0x2e7be13cedb3ff3b413a6a468c0e63db6ed19864',
    );
    expect(address).toBe('0x2E7be13CEDb3Ff3B413A6a468c0E63DB6Ed19864');
  });
  // TODO: add tests for the other functions
});
