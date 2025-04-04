import BN from "bn.js";
import type { BNString, StringifiedType } from "./interfaces.mjs";
/**
 *
 */
declare class Share {
    share: BN;
    shareIndex: BN;
    /**
     *
     * @param shareIndex - index of the share.
     * @param share - share value.
     */
    constructor(shareIndex: BNString, share: BNString);
    /**
     * Creates a share instance from a JSON object.
     *
     * @param value - JSON object.
     * @returns - share instance.
     */
    static fromJSON(value: StringifiedType): Share;
    /**
     * Converts the share to a JSON object.
     *
     * @returns - JSON object.
     */
    toJSON(): StringifiedType;
}
export default Share;
//# sourceMappingURL=share.d.mts.map