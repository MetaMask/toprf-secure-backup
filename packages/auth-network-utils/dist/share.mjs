function $importDefault(module) {
    if (module?.__esModule) {
        return module.default;
    }
    return module;
}
import $BN from "bn.js";
const BN = $importDefault($BN);
/**
 *
 */
class Share {
    /**
     *
     * @param shareIndex - index of the share.
     * @param share - share value.
     */
    constructor(shareIndex, share) {
        this.share = new BN(share, 'hex');
        this.shareIndex = new BN(shareIndex, 'hex');
    }
    /**
     * Creates a share instance from a JSON object.
     *
     * @param value - JSON object.
     * @returns - share instance.
     */
    static fromJSON(value) {
        const { share, shareIndex } = value;
        return new Share(shareIndex, share);
    }
    /**
     * Converts the share to a JSON object.
     *
     * @returns - JSON object.
     */
    toJSON() {
        return {
            share: this.share.toString('hex', 64),
            shareIndex: this.shareIndex.toString('hex', 64),
        };
    }
}
export default Share;
//# sourceMappingURL=share.mjs.map