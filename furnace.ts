/* 
This is Furnace, an implementation of Fernet using XChaCha20-Poly1305 to improve security of the recipe.
This is using the unofficial Fernet v3 spec created by Mike Lodder (https://github.com/mikelodder7/fernet/blob/deccfda5ff8d3c407175a2eace570bd4b7adc5ad/specs/version3.md)
*/

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { bytesToUtf8, utf8ToBytes } from "@noble/ciphers/utils";
import { randomBytes } from "node:crypto";

export class Furnace {
  // Fernet version, must be 0x20 (32) as defined in spec.
  private version: number = 0x20;
  // Private key for XChaCha20
  private key: Uint8Array = new Uint8Array(randomBytes(32));

  constructor(key?: Uint8Array) {
    if (key) this.key = key;
  }

  /**
   * Encrypts a message string using XChaCha20-Poly1305 and encodes into a Fernet v3 token
   * @param {string} message The string that you want to encrypt and encode.
   * @param {Uint8Array} nonce You can provide a nonce, but one will be generated for you
   * @param date This allows you to add a custom datetime, but this should only be used for testing
   * @returns A Fernet token
   */
  public encode(
    message: string,
    nonce: Uint8Array = new Uint8Array(randomBytes(24)),
    date: Date = new Date()
  ): Uint8Array {
    console.log(this.key);
    // Checks nonce length.
    if (nonce.length !== 24)
      throw new Error(
        "Cryptographic nonce doesn't match the expected 192-bit length."
      );
    // Pads UNIX timestamp in seconds to an 64-bit unsigned integer.
    const timestamp = String(Math.round(date.getTime() / 1000)).padStart(
      8,
      "0"
    );
    // Generates additional associated data (AAD) by creating a byte concatenation of the version, timestamp and nonce.
    const aad = new Uint8Array(33);
    aad[0] = this.version;
    aad.set(Uint8Array.from(timestamp, Number), 1);
    aad.set(nonce, 9);

    // Encrypt message using XChaCha20-Poly1305
    const xchacha = xchacha20poly1305(this.key, nonce, aad);
    const text = xchacha.encrypt(utf8ToBytes(message));

    // Add cipher text to AAD to complete Fernet token
    const token = new Uint8Array(text.length + aad.length);
    token.set(aad);
    token.set(text, aad.length);

    console.log(this.version);
    console.log(nonce);
    console.log(aad);
    console.log(utf8ToBytes(message));
    console.log(text);

    return token;
  }

  /**
   * Decodes a provided Fernet token, provided that the instance's key is the same as what encrypted the token.
   * @param token The token you wish to decrypt.
   * @param ttl The time to live expected of the token.
   * @returns The message string
   */
  public decode(token: Uint8Array, ttl?: number): string {
    console.log(this.key);
    // Check token version
    if (token[0] !== 0x20)
      throw new Error(
        `Invalid Fernet version, expected version 32, recieved version ${token[0]}.`
      );

    // Check minimum token length
    if (token.length < 33)
      throw new Error(
        `Invalid token length, expected at least 264 bits, recieved ${
          token.length * 8
        } bits.`
      );

    // Extract timestamp
    const timestamp: number = parseInt(token.slice(1, 9).join(""));

    // Check if TTL has expired if included
    if (ttl && ttl >= 0 && timestamp + ttl < Math.round(Date.now() / 1000))
      throw new Error(`Token has expired.`);

    // Extract AAD and nonce from token
    const text = token.slice(33);
    const nonce = token.slice(9, 33);
    const aad = token.slice(0, 33);

    // Decrypt message and return as string
    const xchacha = xchacha20poly1305(this.key, nonce, aad);
    const message = xchacha.decrypt(text);

    console.log(this.version);
    console.log(nonce);
    console.log(aad);
    console.log(text);
    console.log(message);

    return bytesToUtf8(message);
  }

  /** Encode a Uint8Array as a Base64 string with URL safety. */
  public toBase64URL(token: Uint8Array): string {
    return Buffer.from(token).toString("base64url");
  }

  /** Decodes a Base64URL string to a Uint8Array. */
  public toUint8Array(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, "base64url"));
  }
}
