/**
 * DefaultCryptographicSuite — concrete implementation using:
 *   @noble/curves/ed25519 — Ed25519 key operations and Ed→X25519 conversion
 *   @noble/curves/x25519  — X25519 base scalar multiplication (from ed25519 module)
 *   @noble/hashes/argon2  — Argon2ID key stretching
 *   tweetnacl-sealedbox-js — X25519 sealed box encrypt/decrypt
 *   tweetnacl              — RNG
 */
import { ed25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv, x25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { argon2id } from "@noble/hashes/argon2";
import { createRequire } from "module";
import type { ICryptographicSuite } from "../ports/cryptographic-suite.js";
import { DerivationError } from "../errors.js";

const require = createRequire(import.meta.url);
// tweetnacl-sealedbox-js is a CommonJS module
const sealedBox = require("tweetnacl-sealedbox-js") as {
  seal(msg: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array;
  open(
    box: Uint8Array,
    recipientPublicKey: Uint8Array,
    recipientSecretKey: Uint8Array,
  ): Uint8Array | null;
  overheadLength: number;
};
const nacl = require("tweetnacl") as {
  randomBytes(n: number): Uint8Array;
};

export class DefaultCryptographicSuite implements ICryptographicSuite {
  constructor(private readonly testMode: boolean = false) {}

  deriveEdKeyPair(seed: Uint8Array): { publicKey: Uint8Array; signingKey: Uint8Array } {
    const publicKey = ed25519.getPublicKey(seed);
    return { publicKey, signingKey: seed };
  }

  deriveEcKeyPair(
    seed: Uint8Array,
    curve: string,
  ): { publicKey: Uint8Array; signingKey: Uint8Array } {
    if (curve === "secp256r1" || curve === "P-256") {
      // p256 private key is the seed (as big-endian scalar)
      const privKey = seed.slice(0, 32);
      const pubPoint = p256.getPublicKey(privKey, false); // uncompressed 65 bytes
      return { publicKey: pubPoint.slice(1, 33), signingKey: privKey }; // x coord
    } else if (curve === "secp256k1") {
      const privKey = seed.slice(0, 32);
      const pubPoint = secp256k1.getPublicKey(privKey, false);
      return { publicKey: pubPoint.slice(1, 33), signingKey: privKey };
    }
    throw new DerivationError(`Unsupported curve: ${curve}`);
  }

  edSign(message: Uint8Array, signingKey: Uint8Array): Uint8Array {
    return ed25519.sign(message, signingKey);
  }

  ecSign(message: Uint8Array, seed: Uint8Array, curve: string): Uint8Array {
    if (curve === "secp256r1" || curve === "P-256") {
      const sig = p256.sign(message, seed);
      return sig.toCompactRawBytes();
    } else if (curve === "secp256k1") {
      const sig = secp256k1.sign(message, seed);
      return sig.toCompactRawBytes();
    }
    throw new DerivationError(`Unsupported curve: ${curve}`);
  }

  stretchKey(
    password: Uint8Array,
    salt: Uint8Array,
    outLength: number,
    opsLimit: number,
    memLimit: number,
  ): Uint8Array {
    return argon2id(password, salt, {
      t: opsLimit,
      m: memLimit, // in KiB
      p: 1,
      dkLen: outLength,
    });
  }

  generateRandom(size: number): Uint8Array {
    return nacl.randomBytes(size);
  }

  sealedBoxEncrypt(plaintext: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return sealedBox.seal(plaintext, publicKey);
  }

  sealedBoxDecrypt(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
  ): Uint8Array | null {
    return sealedBox.open(ciphertext, publicKey, privateKey);
  }

  edPublicToX25519(edPublicKey: Uint8Array): Uint8Array {
    return edwardsToMontgomeryPub(edPublicKey);
  }

  edPrivateToX25519(edSigningKey: Uint8Array): Uint8Array {
    // edSigningKey is 64 bytes: seed (32) + pubkey (32)
    // edwardsToMontgomeryPriv takes the 32-byte seed
    const seed = edSigningKey.slice(0, 32);
    return edwardsToMontgomeryPriv(seed);
  }

  x25519Base(privateKey: Uint8Array): Uint8Array {
    return x25519.scalarMultBase(privateKey);
  }
}
