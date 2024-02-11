/* 
This is Furnace, an implementation of Fernet using XChaCha20-Poly1305 to improve security of the recipe.
This is using the unofficial Fernet v3 spec created by Mike Lodder (https://github.com/mikelodder7/fernet/blob/deccfda5ff8d3c407175a2eace570bd4b7adc5ad/specs/version3.md)
*/

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { bytesToUtf8, utf8ToBytes } from "@noble/ciphers/utils";
import { randomBytes } from "node:crypto";

enum FurnaceErrorCode {
  "NONCE_LENGTH" = 0,
  "INVALID_FERNET_VERSION" = 1,
  "INVALID_TOKEN_LENGTH" = 2,
  "TOKEN_EXPIRED" = 3,
}

enum FurnaceErrorMessage {
  "Cryptographic nonce doesn't match the expected 192-bit length." = 0,
  "Invalid Fernet version, expected version 32." = 1,
  "Invalid token length, expected at least 264 bits." = 2,
  "Token has expired." = 3,
}

export class FurnaceError extends Error {
  code: FurnaceErrorCode;
  msg: FurnaceErrorMessage;
  constructor(code: FurnaceErrorCode, msg?: FurnaceErrorMessage) {
    super(msg.toString());
    Object.setPrototypeOf(this, FurnaceError.prototype);
    code = this.code;
    msg = this.msg;
  }

  toString() {
    return `[${Date.now().toLocaleString}] FURNACE: ${this.code} - ${this.msg}`;
  }
}

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
   * @returns A Fernet token
   */
  public encode(
    message: string,
    nonce: Uint8Array = new Uint8Array(randomBytes(24))
  ): Uint8Array {
    // Checks nonce length.
    if (nonce.length !== 24) throw new FurnaceError(0);
    // Pads UNIX timestamp in seconds to an 64-bit unsigned integer.
    const timestamp = Math.round(Date.now() / 1000);
    const buffer = new ArrayBuffer(8);
    const dataview = new DataView(buffer);
    dataview.setBigUint64(0, BigInt(timestamp), false);
    // Generates additional associated data (AAD) by creating a byte concatenation of the version, timestamp and nonce.
    const aad = new Uint8Array(33);
    aad[0] = this.version;
    aad.set(new Uint8Array(buffer), 1);
    aad.set(nonce, 9);

    // Encrypt message using XChaCha20-Poly1305
    const xchacha = xchacha20poly1305(this.key, nonce, aad);
    const text = xchacha.encrypt(utf8ToBytes(message));

    // Add cipher text to AAD to complete Fernet token
    const token = new Uint8Array(text.length + aad.length);
    token.set(aad);
    token.set(text, aad.length);

    return token;
  }

  /**
   * Decodes a provided Fernet token, provided that the instance's key is the same as what encrypted the token.
   * @param token The token you wish to decrypt.
   * @param ttl The time to live expected of the token.
   * @returns The message string
   */
  public decode(token: Uint8Array, ttl?: number): string {
    // Check token version
    if (token[0] !== 0x20) throw new FurnaceError(1);

    // Check minimum token length
    if (token.length < 33) throw new FurnaceError(2);

    // Extract timestamp
    const timestamp: number = parseInt(token.slice(1, 9).join(""));

    // Check if TTL has expired if included
    if (ttl && ttl >= 0 && timestamp + ttl < Math.round(Date.now() / 1000))
      throw new FurnaceError(3);

    // Extract AAD and nonce from token
    const text = token.slice(33);
    const nonce = token.slice(9, 33);
    const aad = token.slice(0, 33);

    // Decrypt message and return as string
    const xchacha = xchacha20poly1305(this.key, nonce, aad);
    const message = xchacha.decrypt(text);

    return bytesToUtf8(message);
  }
}

/** Encode a Uint8Array as a Base64 string with URL safety. */
export function toBase64URL(token: Uint8Array): string {
  return Buffer.from(token).toString("base64url");
}

/** Decodes a Base64URL string to a Uint8Array. */
export function toUint8Array(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64url"));
}
