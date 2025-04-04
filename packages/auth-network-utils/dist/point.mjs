function $importDefault(module) {
    if (module?.__esModule) {
        return module.default;
    }
    return module;
}
import $BN from "bn.js";
const BN = $importDefault($BN);
/**
 * Represents a point on an elliptic curve.
 */
class Point {
    /**
     *
     * @param xCoordinate - x coordinate of the point.
     * @param yCoordinate - y coordinate of the point.
     * @param ecCurve - elliptic curve instance.
     */
    constructor(xCoordinate, yCoordinate, ecCurve) {
        this.xCoordinate = new BN(xCoordinate, 'hex');
        this.yCoordinate = new BN(yCoordinate, 'hex');
        this.ecCurve = ecCurve;
    }
    /**
     * Encodes the point in array or elliptic-compressed format to a buffer.
     *
     * @param enc - encoding type.
     * @returns - encoded point.
     */
    encode(enc) {
        switch (enc) {
            case 'arr':
                return Buffer.concat([
                    Buffer.from('04', 'hex'),
                    Buffer.from(this.xCoordinate.toString('hex', 64), 'hex'),
                    Buffer.from(this.yCoordinate.toString('hex', 64), 'hex'),
                ]);
            case 'elliptic-compressed': {
                const key = this.ecCurve.keyFromPublic({
                    x: this.xCoordinate.toString('hex', 64),
                    y: this.yCoordinate.toString('hex', 64),
                }, 'hex');
                return Buffer.from(key.getPublic(true, 'hex'));
            }
            default:
                throw new Error("encoding doesn't exist in Point");
        }
    }
}
export default Point;
//# sourceMappingURL=point.mjs.map