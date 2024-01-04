/* 
    This is Furnace, an implementation of Fernet using XChaCha20-Poly1305 to improve security of the recipe.
    This is using the unofficial Fernet v3 spec created by Mike Lodder (https://github.com/mikelodder7/fernet/blob/deccfda5ff8d3c407175a2eace570bd4b7adc5ad/specs/version3.md)
*/

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { utf8ToBytes } from "@noble/ciphers/utils";
import { randomBytes } from "node:crypto";

export class Furnace {
  // Fernet version, must be 0x20 (32) as defined in spec.
  private version: number = 0x20;
  // Private key for XChaCha20
  private key: Uint8Array = randomBytes(32);

  public encode(
    message: string,
    nonce: Uint8Array = randomBytes(24),
    date: Date = new Date()
  ): string | Uint8Array {
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

    return token;
  }
}
