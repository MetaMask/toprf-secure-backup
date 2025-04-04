"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bn_js_1 = __importDefault(require("bn.js"));
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
        this.xCoordinate = new bn_js_1.default(xCoordinate, 'hex');
        this.yCoordinate = new bn_js_1.default(yCoordinate, 'hex');
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
exports.default = Point;
//# sourceMappingURL=point.cjs.map