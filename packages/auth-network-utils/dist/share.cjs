"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bn_js_1 = __importDefault(require("bn.js"));
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
        this.share = new bn_js_1.default(share, 'hex');
        this.shareIndex = new bn_js_1.default(shareIndex, 'hex');
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
exports.default = Share;
//# sourceMappingURL=share.cjs.map