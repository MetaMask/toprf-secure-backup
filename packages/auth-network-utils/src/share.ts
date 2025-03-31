import BN from 'bn.js';

import type { BNString, StringifiedType } from './interfaces';

/**
 *
 */
class Share {
  share: BN;

  shareIndex: BN;

  /**
   *
   * @param shareIndex - index of the share.
   * @param share - share value.
   */
  constructor(shareIndex: BNString, share: BNString) {
    this.share = new BN(share, 'hex');
    this.shareIndex = new BN(shareIndex, 'hex');
  }

  /**
   * Creates a share instance from a JSON object.
   *
   * @param value - JSON object.
   * @returns - share instance.
   */
  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value;
    return new Share(shareIndex as BNString, share as BNString);
  }

  /**
   * Converts the share to a JSON object.
   *
   * @returns - JSON object.
   */
  toJSON(): StringifiedType {
    return {
      share: this.share.toString('hex', 64),
      shareIndex: this.shareIndex.toString('hex', 64),
    };
  }
}

export default Share;
