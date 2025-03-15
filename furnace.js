"use strict";
/*
This is Furnace, an implementation of Fernet using XChaCha20-Poly1305 to improve security of the recipe.
This is using the unofficial Fernet v3 spec created by Mike Lodder (https://github.com/mikelodder7/fernet/blob/deccfda5ff8d3c407175a2eace570bd4b7adc5ad/specs/version3.md)
*/
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Furnace = exports.FurnaceError = void 0;
exports.toBase64URL = toBase64URL;
exports.toUint8Array = toUint8Array;
var chacha_1 = require("@noble/ciphers/chacha");
var utils_1 = require("@noble/ciphers/utils");
var node_crypto_1 = require("node:crypto");
var FurnaceErrorMessage;
(function (FurnaceErrorMessage) {
    FurnaceErrorMessage[FurnaceErrorMessage["Cryptographic nonce doesn't match the expected 192-bit length."] = 0] = "Cryptographic nonce doesn't match the expected 192-bit length.";
    FurnaceErrorMessage[FurnaceErrorMessage["Invalid Fernet version, expected version 32."] = 1] = "Invalid Fernet version, expected version 32.";
    FurnaceErrorMessage[FurnaceErrorMessage["Invalid token length, expected at least 264 bits."] = 2] = "Invalid token length, expected at least 264 bits.";
    FurnaceErrorMessage[FurnaceErrorMessage["Token has expired."] = 3] = "Token has expired.";
})(FurnaceErrorMessage || (FurnaceErrorMessage = {}));
var FurnaceError = /** @class */ (function (_super) {
    __extends(FurnaceError, _super);
    function FurnaceError(message) {
        var _this = _super.call(this, message.toString()) || this;
        Object.setPrototypeOf(_this, FurnaceError.prototype);
        return _this;
    }
    FurnaceError.prototype.toString = function () {
        return "[".concat(Date.now().toLocaleString("en-GB"), "] FURNACE: ").concat(this.message);
    };
    return FurnaceError;
}(Error));
exports.FurnaceError = FurnaceError;
var Furnace = /** @class */ (function () {
    function Furnace(key) {
        // Fernet version, must be 0x20 (32) as defined in spec.
        this.version = 0x20;
        // Private key for XChaCha20
        this.key = new Uint8Array((0, node_crypto_1.randomBytes)(32));
        if (key)
            this.key = key;
    }
    /**
     * Encrypts a message string using XChaCha20-Poly1305 and encodes into a Fernet v3 token
     * @param {string} message The string that you want to encrypt and encode.
     * @param {Uint8Array} nonce You can provide a nonce, but one will be generated for you
     * @returns A Fernet token
     */
    Furnace.prototype.encode = function (message, nonce) {
        if (nonce === void 0) { nonce = new Uint8Array((0, node_crypto_1.randomBytes)(24)); }
        // Checks nonce length.
        if (nonce.length !== 24)
            throw new FurnaceError(0);
        // Pads UNIX timestamp in seconds to an 64-bit unsigned integer.
        var timestamp = Math.round(Date.now() / 1000);
        var buffer = new ArrayBuffer(8);
        var dataview = new DataView(buffer);
        dataview.setBigUint64(0, BigInt(timestamp), false);
        // Generates additional associated data (AAD) by creating a byte concatenation of the version, timestamp and nonce.
        var aad = new Uint8Array(33);
        aad[0] = this.version;
        aad.set(new Uint8Array(buffer), 1);
        aad.set(nonce, 9);
        // Encrypt message using XChaCha20-Poly1305
        var xchacha = (0, chacha_1.xchacha20poly1305)(this.key, nonce, aad);
        var text = xchacha.encrypt((0, utils_1.utf8ToBytes)(message));
        // Add cipher text to AAD to complete Fernet token
        var token = new Uint8Array(text.length + aad.length);
        token.set(aad);
        token.set(text, aad.length);
        return token;
    };
    /**
     * Decodes a provided Fernet token, provided that the instance's key is the same as what encrypted the token.
     * @param token The token you wish to decrypt.
     * @param ttl The time to live expected of the token.
     * @returns The message string
     */
    Furnace.prototype.decode = function (token, ttl) {
        // Check token version
        if (token[0] !== 0x20)
            throw new FurnaceError(1);
        // Check minimum token length
        if (token.length < 33)
            throw new FurnaceError(2);
        // Extract timestamp
        var tsBytes = token.slice(1, 9);
        var tsBuffer = Buffer.from(tsBytes);
        var timestamp = Number(tsBuffer.readBigInt64BE());
        if (ttl)
            console.log("FURNACE: Current unix time in milliseconds is ".concat(Math.round(Date.now() / 1000), ", TS+TTL is ").concat(timestamp + ttl));
        // Check if TTL has expired if included
        if (ttl !== undefined && (ttl < 0 || timestamp + ttl < Math.round(Date.now() / 1000)))
            throw new FurnaceError(3);
        // Extract AAD and nonce from token
        var text = token.slice(33);
        var nonce = token.slice(9, 33);
        var aad = token.slice(0, 33);
        // Decrypt message and return as string
        var xchacha = (0, chacha_1.xchacha20poly1305)(this.key, nonce, aad);
        var message = xchacha.decrypt(text);
        return (0, utils_1.bytesToUtf8)(message);
    };
    return Furnace;
}());
exports.Furnace = Furnace;
/** Encode a Uint8Array as a Base64 string with URL safety. */
function toBase64URL(token) {
    return Buffer.from(token).toString("base64url");
}
/** Decodes a Base64URL string to a Uint8Array. */
function toUint8Array(base64) {
    // Add basic validation for base64url format
    if (!/^[A-Za-z0-9_-]*$/.test(base64)) {
        throw new Error("Invalid base64url string");
    }
    return new Uint8Array(Buffer.from(base64, "base64url"));
}
