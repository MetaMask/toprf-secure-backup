"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRandomNonce = exports.waitFor = exports.capitalizeFirstLetter = exports.generateEmptyBNArray = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
/**
 * Generates an array of empty BN objects
 *
 * @param length - The length of the array
 * @returns The array of empty BN objects
 */
function generateEmptyBNArray(length) {
    return Array.from({ length }, () => new bn_js_1.default(0));
}
exports.generateEmptyBNArray = generateEmptyBNArray;
/**
 * Capitalizes the first letter of a string
 *
 * @param str - The string to capitalize
 * @returns The string with the first letter capitalized
 */
function capitalizeFirstLetter(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
exports.capitalizeFirstLetter = capitalizeFirstLetter;
/**
 * Waits for a specified number of milliseconds
 *
 * @param ms - The number of milliseconds to wait
 * @returns A promise that resolves after the specified number of milliseconds
 */
async function waitFor(ms = 2000) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}
exports.waitFor = waitFor;
/**
 * Generates a random nonce
 *
 * @param curve - The elliptic curve to use
 * @returns The random nonce
 */
function getRandomNonce(curve) {
    const privateKey = curve.genKeyPair().getPrivate();
    const privateKeyBuffer = privateKey.toArrayLike(Buffer, undefined, 32);
    return new bn_js_1.default(privateKeyBuffer);
}
exports.getRandomNonce = getRandomNonce;
//# sourceMappingURL=helpers.cjs.map