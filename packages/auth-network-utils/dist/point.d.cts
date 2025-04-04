/// <reference types="node" />
/// <reference types="node" />
import BN from "bn.js";
import type { ec as EC } from "elliptic";
import type { BNString } from "./interfaces.cjs";
/**
 * Represents a point on an elliptic curve.
 */
declare class Point {
    /**
     * x coordinate of the point.
     */
    xCoordinate: BN;
    /**
     * y coordinate of the point.
     */
    yCoordinate: BN;
    /**
     * elliptic curve instance.
     */
    ecCurve: EC;
    /**
     *
     * @param xCoordinate - x coordinate of the point.
     * @param yCoordinate - y coordinate of the point.
     * @param ecCurve - elliptic curve instance.
     */
    constructor(xCoordinate: BNString, yCoordinate: BNString, ecCurve: EC);
    /**
     * Encodes the point in array or elliptic-compressed format to a buffer.
     *
     * @param enc - encoding type.
     * @returns - encoded point.
     */
    encode(enc: string): Buffer;
}
export default Point;
//# sourceMappingURL=point.d.cts.map