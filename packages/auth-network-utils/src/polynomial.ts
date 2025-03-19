import BN from 'bn.js';
import type { ec as EC } from 'elliptic';

import type { BNString } from './interfaces';
import Share from './share';

export type ShareMap = {
  [x: string]: Share;
};

class Polynomial {
  polynomial: BN[];

  ecCurve: EC;

  constructor(polynomial: BN[], ecCurve: EC) {
    this.polynomial = polynomial;
    this.ecCurve = ecCurve;
  }

  getThreshold(): number {
    return this.polynomial.length;
  }

  polyEval(x: BNString): BN {
    const tmpX = new BN(x, 'hex');
    let xi = new BN(tmpX);
    let sum = new BN(0);
    sum = sum.add(this.polynomial[0]);

    const { n } = this.ecCurve;
    if (!n) {
      throw new Error('Curve is not set');
    }

    for (const coeff of this.polynomial.slice(1)) {
      const tmp = xi.mul(coeff);
      sum = sum.add(tmp);
      sum = sum.umod(n);
      xi = xi.mul(new BN(tmpX));
      xi = xi.umod(n);
    }
    return sum;
  }

  generateShares(shareIndexes: BNString[]): ShareMap {
    const newShareIndexes = shareIndexes.map((index) => {
      if (typeof index === 'number') {
        return new BN(index);
      }
      if (index instanceof BN) {
        return index;
      }
      if (typeof index === 'string') {
        return new BN(index, 'hex');
      }
      return index;
    });

    const shares: ShareMap = {};
    for (const index of newShareIndexes) {
      shares[index.toString('hex', 64)] = new Share(
        index,
        this.polyEval(index),
      );
    }
    return shares;
  }
}

export default Polynomial;
