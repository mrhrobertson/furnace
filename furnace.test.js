"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var globals_1 = require("@jest/globals");
var furnace_1 = require("./furnace");
(0, globals_1.describe)("Furnace", function () {
    var furnace;
    var testMessage = "Hello, World!";
    var testKey = new Uint8Array(32).fill(1); // Test key filled with 1's
    (0, globals_1.beforeEach)(function () {
        furnace = new furnace_1.Furnace(testKey);
    });
    (0, globals_1.describe)("constructor()", function () {
        (0, globals_1.it)("[C01] generates random key when none provided", function () {
            var furnace1 = new furnace_1.Furnace();
            var furnace2 = new furnace_1.Furnace();
            (0, globals_1.expect)(furnace1['key']).not.toEqual(furnace2['key']);
        });
        (0, globals_1.it)("[C02] uses provided key", function () {
            var customKey = new Uint8Array(32).fill(5);
            var furnace = new furnace_1.Furnace(customKey);
            (0, globals_1.expect)(furnace['key']).toEqual(customKey);
        });
    });
    (0, globals_1.describe)("encode()", function () {
        (0, globals_1.it)("[E01] produces valid Fernet v3 token", function () {
            var token = furnace.encode(testMessage);
            (0, globals_1.expect)(token).toBeInstanceOf(Uint8Array);
            (0, globals_1.expect)(token.length).toBeGreaterThan(33);
            (0, globals_1.expect)(token[0]).toBe(0x20);
        });
        (0, globals_1.it)("[E02] rejects invalid nonce length", function () {
            var invalidNonce = new Uint8Array(16);
            (0, globals_1.expect)(function () { return furnace.encode(testMessage, invalidNonce); }).toThrow(furnace_1.FurnaceError);
        });
        (0, globals_1.it)("[E03] generates unique tokens with different nonces", function () {
            var nonce1 = new Uint8Array(24).fill(1);
            var nonce2 = new Uint8Array(24).fill(2);
            var token1 = furnace.encode(testMessage, nonce1);
            var token2 = furnace.encode(testMessage, nonce2);
            (0, globals_1.expect)(Buffer.from(token1).toString()).not.toBe(Buffer.from(token2).toString());
        });
        (0, globals_1.it)("[E04] handles very large messages", function () {
            var largeMessage = "A".repeat(1000000);
            var token = furnace.encode(largeMessage);
            var decoded = furnace.decode(token);
            (0, globals_1.expect)(decoded).toBe(largeMessage);
        });
        (0, globals_1.it)("[E05] generates unique tokens for same message", function () {
            var token1 = furnace.encode(testMessage);
            var token2 = furnace.encode(testMessage);
            (0, globals_1.expect)(Buffer.from(token1).toString()).not.toBe(Buffer.from(token2).toString());
        });
    });
    (0, globals_1.describe)("decode()", function () {
        (0, globals_1.it)("[D01] decrypts message correctly", function () {
            var token = furnace.encode(testMessage);
            var decoded = furnace.decode(token);
            (0, globals_1.expect)(decoded).toBe(testMessage);
        });
        (0, globals_1.it)("[D02] rejects invalid version", function () {
            var token = furnace.encode(testMessage);
            token[0] = 0x10;
            (0, globals_1.expect)(function () { return furnace.decode(token); }).toThrow(furnace_1.FurnaceError);
        });
        (0, globals_1.it)("[D03] rejects expired token", function () {
            var token = furnace.encode(testMessage);
            (0, globals_1.expect)(function () { return furnace.decode(token, -1); }).toThrow(furnace_1.FurnaceError);
        });
        (0, globals_1.it)("[D04] rejects short token", function () {
            var shortToken = new Uint8Array(32);
            (0, globals_1.expect)(function () { return furnace.decode(shortToken); }).toThrow(furnace_1.FurnaceError);
        });
        (0, globals_1.it)("[D05] accepts valid TTL", function () {
            var token = furnace.encode(testMessage);
            var decoded = furnace.decode(token, 3600); // 1 hour TTL
            (0, globals_1.expect)(decoded).toBe(testMessage);
        });
        (0, globals_1.it)("[D06] rejects modified ciphertext", function () {
            var token = furnace.encode(testMessage);
            // Modify the ciphertext portion
            token[token.length - 1] ^= 1;
            (0, globals_1.expect)(function () { return furnace.decode(token); }).toThrow();
        });
        (0, globals_1.it)("[D07] rejects modified timestamp", function () {
            var token = furnace.encode(testMessage);
            // Modify timestamp bytes
            token[1] ^= 1;
            (0, globals_1.expect)(function () { return furnace.decode(token); }).toThrow();
        });
    });
    (0, globals_1.describe)("Base64URL utilities", function () {
        (0, globals_1.it)("[B01] converts between Uint8Array and base64url", function () {
            var original = new Uint8Array([1, 2, 3, 4, 5]);
            var base64 = (0, furnace_1.toBase64URL)(original);
            var converted = (0, furnace_1.toUint8Array)(base64);
            (0, globals_1.expect)(converted).toEqual(original);
        });
        (0, globals_1.it)("[B02] handles empty array conversion", function () {
            var empty = new Uint8Array(0);
            var base64 = (0, furnace_1.toBase64URL)(empty);
            var converted = (0, furnace_1.toUint8Array)(base64);
            (0, globals_1.expect)(converted).toEqual(empty);
        });
        (0, globals_1.it)("[B03] handles special Base64URL characters", function () {
            // Create array that will generate Base64URL with - and _
            var data = new Uint8Array([251, 255, 191]);
            var base64 = (0, furnace_1.toBase64URL)(data);
            var converted = (0, furnace_1.toUint8Array)(base64);
            (0, globals_1.expect)(converted).toEqual(data);
        });
        (0, globals_1.it)("[B04] rejects invalid base64url characters", function () {
            (0, globals_1.expect)(function () { return (0, furnace_1.toUint8Array)("!@#invalid"); }).toThrow("Invalid base64url string");
            (0, globals_1.expect)(function () { return (0, furnace_1.toUint8Array)("abc!def"); }).toThrow("Invalid base64url string");
            (0, globals_1.expect)(function () { return (0, furnace_1.toUint8Array)("abc=def"); }).toThrow("Invalid base64url string");
            (0, globals_1.expect)(function () { return (0, furnace_1.toUint8Array)("abc/def"); }).toThrow("Invalid base64url string");
            (0, globals_1.expect)(function () { return (0, furnace_1.toUint8Array)("abc+def"); }).toThrow("Invalid base64url string");
        });
    });
    (0, globals_1.describe)("End-to-end encryption", function () {
        (0, globals_1.it)("[EE01] handles various text types", function () {
            var messages = [
                "Simple text",
                "Special chars: !@#$%^&*()",
                "Unicode: 你好，世界",
                "🎉 Emojis 🚀",
                "",
                "A".repeat(1000)
            ];
            messages.forEach(function (msg) {
                var token = furnace.encode(msg);
                var decoded = furnace.decode(token);
                (0, globals_1.expect)(decoded).toBe(msg);
            });
        });
        (0, globals_1.it)("[EE02] fails with wrong key", function () {
            var token = furnace.encode(testMessage);
            var wrongKey = new Uint8Array(32).fill(2);
            var wrongFurnace = new furnace_1.Furnace(wrongKey);
            (0, globals_1.expect)(function () { return wrongFurnace.decode(token); }).toThrow();
        });
        (0, globals_1.it)("[EE03] maintains data integrity across multiple encode/decode cycles", function () {
            var message = "Test message";
            var token = furnace.encode(message);
            for (var i = 0; i < 5; i++) {
                var decoded = furnace.decode(token);
                token = furnace.encode(decoded);
                (0, globals_1.expect)(furnace.decode(token)).toBe(message);
            }
        });
        (0, globals_1.it)("[EE04] handles concurrent operations", function () { return __awaiter(void 0, void 0, void 0, function () {
            var messages, operations, results;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        messages = Array(10).fill(0).map(function (_, i) { return "Message ".concat(i); });
                        operations = messages.map(function (msg) { return __awaiter(void 0, void 0, void 0, function () {
                            var token, decoded;
                            return __generator(this, function (_a) {
                                token = furnace.encode(msg);
                                decoded = furnace.decode(token);
                                return [2 /*return*/, { original: msg, decoded: decoded }];
                            });
                        }); });
                        return [4 /*yield*/, Promise.all(operations)];
                    case 1:
                        results = _a.sent();
                        results.forEach(function (_a) {
                            var original = _a.original, decoded = _a.decoded;
                            (0, globals_1.expect)(decoded).toBe(original);
                        });
                        return [2 /*return*/];
                }
            });
        }); });
    });
});
