import { describe, expect, it, beforeEach } from '@jest/globals';

import { Furnace, FurnaceError, toBase64URL, toUint8Array } from "./furnace";

describe("Furnace", () => {
  let furnace: Furnace;
  const testMessage = "Hello, World!";
  const testKey = new Uint8Array(32).fill(1); // Test key filled with 1's

  beforeEach(() => {
    furnace = new Furnace(testKey);
  });

  describe("constructor()", () => {
    it("[C01] generates random key when none provided", () => {
      const furnace1 = new Furnace();
      const furnace2 = new Furnace();
      expect(furnace1['key']).not.toEqual(furnace2['key']);
    });

    it("[C02] uses provided key", () => {
      const customKey = new Uint8Array(32).fill(5);
      const furnace = new Furnace(customKey);
      expect(furnace['key']).toEqual(customKey);
    });
  });

  describe("encode()", () => {
    it("[E01] produces valid Fernet v3 token", () => {
      const token = furnace.encode(testMessage);
      expect(token).toBeInstanceOf(Uint8Array);
      expect(token.length).toBeGreaterThan(33);
      expect(token[0]).toBe(0x20);
    });

    it("[E02] rejects invalid nonce length", () => {
      const invalidNonce = new Uint8Array(16);
      expect(() => furnace.encode(testMessage, invalidNonce)).toThrow(FurnaceError);
    });

    it("[E03] generates unique tokens with different nonces", () => {
      const nonce1 = new Uint8Array(24).fill(1);
      const nonce2 = new Uint8Array(24).fill(2);
      
      const token1 = furnace.encode(testMessage, nonce1);
      const token2 = furnace.encode(testMessage, nonce2);
      
      expect(Buffer.from(token1).toString()).not.toBe(Buffer.from(token2).toString());
    });

    it("[E04] handles very large messages", () => {
      const largeMessage = "A".repeat(1000000);
      const token = furnace.encode(largeMessage);
      const decoded = furnace.decode(token);
      expect(decoded).toBe(largeMessage);
    });

    it("[E05] generates unique tokens for same message", () => {
      const token1 = furnace.encode(testMessage);
      const token2 = furnace.encode(testMessage);
      expect(Buffer.from(token1).toString()).not.toBe(Buffer.from(token2).toString());
    });
  });

  describe("decode()", () => {
    it("[D01] decrypts message correctly", () => {
      const token = furnace.encode(testMessage);
      const decoded = furnace.decode(token);
      expect(decoded).toBe(testMessage);
    });

    it("[D02] rejects invalid version", () => {
      const token = furnace.encode(testMessage);
      token[0] = 0x10;
      expect(() => furnace.decode(token)).toThrow(FurnaceError);
    });

    it("[D03] rejects expired token", () => {
      const token = furnace.encode(testMessage);
      expect(() => furnace.decode(token, -1)).toThrow(FurnaceError);
    });

    it("[D04] rejects short token", () => {
      const shortToken = new Uint8Array(32);
      expect(() => furnace.decode(shortToken)).toThrow(FurnaceError);
    });

    it("[D05] accepts valid TTL", () => {
      const token = furnace.encode(testMessage);
      const decoded = furnace.decode(token, 3600); // 1 hour TTL
      expect(decoded).toBe(testMessage);
    });

    it("[D06] rejects modified ciphertext", () => {
      const token = furnace.encode(testMessage);
      // Modify the ciphertext portion
      token[token.length - 1] ^= 1;
      expect(() => furnace.decode(token)).toThrow();
    });

    it("[D07] rejects modified timestamp", () => {
      const token = furnace.encode(testMessage);
      // Modify timestamp bytes
      token[1] ^= 1;
      expect(() => furnace.decode(token)).toThrow();
    });
  });

  describe("Base64URL utilities", () => {
    it("[B01] converts between Uint8Array and base64url", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5]);
      const base64 = toBase64URL(original);
      const converted = toUint8Array(base64);
      expect(converted).toEqual(original);
    });

    it("[B02] handles empty array conversion", () => {
      const empty = new Uint8Array(0);
      const base64 = toBase64URL(empty);
      const converted = toUint8Array(base64);
      expect(converted).toEqual(empty);
    });

    it("[B03] handles special Base64URL characters", () => {
      // Create array that will generate Base64URL with - and _
      const data = new Uint8Array([251, 255, 191]);
      const base64 = toBase64URL(data);
      const converted = toUint8Array(base64);
      expect(converted).toEqual(data);
    });

    it("[B04] rejects invalid base64url characters", () => {
      expect(() => toUint8Array("!@#invalid")).toThrow("Invalid base64url string");
      expect(() => toUint8Array("abc!def")).toThrow("Invalid base64url string");
      expect(() => toUint8Array("abc=def")).toThrow("Invalid base64url string");
      expect(() => toUint8Array("abc/def")).toThrow("Invalid base64url string");
      expect(() => toUint8Array("abc+def")).toThrow("Invalid base64url string");
    });
  });

  describe("End-to-end encryption", () => {
    it("[EE01] handles various text types", () => {
      const messages = [
        "Simple text",
        "Special chars: !@#$%^&*()",
        "Unicode: 你好，世界",
        "🎉 Emojis 🚀",
        "",
        "A".repeat(1000)
      ];

      messages.forEach(msg => {
        const token = furnace.encode(msg);
        const decoded = furnace.decode(token);
        expect(decoded).toBe(msg);
      });
    });

    it("[EE02] fails with wrong key", () => {
      const token = furnace.encode(testMessage);
      const wrongKey = new Uint8Array(32).fill(2);
      const wrongFurnace = new Furnace(wrongKey);
      
      expect(() => wrongFurnace.decode(token)).toThrow();
    });

    it("[EE03] maintains data integrity across multiple encode/decode cycles", () => {
      const message = "Test message";
      let token = furnace.encode(message);
      
      for (let i = 0; i < 5; i++) {
        const decoded = furnace.decode(token);
        token = furnace.encode(decoded);
        expect(furnace.decode(token)).toBe(message);
      }
    });

    it("[EE04] handles concurrent operations", async () => {
      const messages = Array(10).fill(0).map((_, i) => `Message ${i}`);
      const operations = messages.map(async msg => {
        const token = furnace.encode(msg);
        const decoded = furnace.decode(token);
        return { original: msg, decoded };
      });

      const results = await Promise.all(operations);
      results.forEach(({ original, decoded }) => {
        expect(decoded).toBe(original);
      });
    });
  });
}); 