/**
 * CESR encoding/decoding helpers using cesr-ts Matter class.
 *
 * cesr-ts provides a class-based API. We use it for encoding/decoding
 * CESR primitives (Matter subclasses).
 */
import { Matter, Verfer as CesrVerfer, Diger as CesrDiger, parseMatterFromText } from "cesr-ts";
import { DerivationError } from "./errors.js";

// ── CESR code constants ───────────────────────────────────────────────

/** Matter derivation code constants. */
export const MtrDex = {
  Ed25519_Seed: "A",       // 44 chars, 32 bytes raw
  Ed25519N: "B",           // 44 chars, 32 bytes raw (non-transferable)
  X25519: "C",             // 44 chars, 32 bytes raw
  Ed25519: "D",            // 44 chars, 32 bytes raw
  Blake3_256: "E",         // 44 chars, 32 bytes raw
  X25519_Private: "O",     // 44 chars, 32 bytes raw
  Salt_128: "0A",          // 24 chars, 16 bytes raw
  X25519_Cipher_Seed: "P", // 124 chars, 92 bytes raw (encrypts 44-char seed qb64 = 44+48=92)
  X25519_Cipher_Salt: "1AAH", // 100 chars, 72 bytes raw (encrypts 24-char salt qb64 = 24+48=72)
} as const;

// ── Encoding / Decoding ───────────────────────────────────────────────

/**
 * Encode raw bytes to qb64 using the specified CESR code.
 * Uses cesr-ts Matter class for accurate CESR encoding.
 */
export function matterEncode(raw: Uint8Array, code: string): string {
  const m = new Matter({ raw, code });
  return m.qb64;
}

/**
 * Decode qb64 string to raw bytes.
 * Uses parseMatterFromText from cesr-ts.
 */
export function matterDecode(qb64: string): Uint8Array {
  const encoded = new TextEncoder().encode(qb64);
  const m = parseMatterFromText(encoded);
  return m.raw;
}

// ── Verfer (public verification key) ─────────────────────────────────

/** Wrapped Ed25519 or Ed25519N public verification key. */
export interface Verfer {
  raw: Uint8Array;
  code: string;
  qb64: string;
  qb64b: Uint8Array;
  transferable: boolean;
}

/**
 * Create a Verfer from raw 32-byte Ed25519 public key bytes.
 */
export function makeVerfer(raw: Uint8Array, transferable: boolean): Verfer {
  const code = transferable ? MtrDex.Ed25519 : MtrDex.Ed25519N;
  const v = new CesrVerfer({ raw, code });
  const qb64 = v.qb64;
  return {
    raw: raw.slice(),
    code,
    qb64,
    qb64b: new TextEncoder().encode(qb64),
    transferable,
  };
}

/**
 * Create a Verfer from a qb64 string.
 */
export function verferFromQb64(qb64: string): Verfer {
  const code = qb64[0];
  const transferable = code === MtrDex.Ed25519;
  const raw = matterDecode(qb64);
  return {
    raw,
    code,
    qb64,
    qb64b: new TextEncoder().encode(qb64),
    transferable,
  };
}

// ── Diger (digest) ────────────────────────────────────────────────────

/** Wrapped digest. */
export interface Diger {
  raw: Uint8Array;
  code: string;
  qb64: string;
  qb64b: Uint8Array;
}

/**
 * Create a Diger from raw digest bytes.
 */
export function makeDiger(raw: Uint8Array, code: string = MtrDex.Blake3_256): Diger {
  const d = new CesrDiger({ raw, code });
  const qb64 = d.qb64;
  return {
    raw: raw.slice(),
    code,
    qb64,
    qb64b: new TextEncoder().encode(qb64),
  };
}

/**
 * Create a Diger from a qb64 string.
 */
export function digerFromQb64(qb64: string): Diger {
  const raw = matterDecode(qb64);
  const code = qb64[0];
  return {
    raw,
    code,
    qb64,
    qb64b: new TextEncoder().encode(qb64),
  };
}

// ── Indexed / Unindexed Signatures ───────────────────────────────────

/** An indexed signature (Siger). */
export interface IndexedSig {
  index: number;
  ondex: number | null;
  raw: Uint8Array;
  qb64: string;
}

/** An unindexed signature (Cigar). */
export interface UnindexedSig {
  raw: Uint8Array;
  verferQb64: string;
}

/** Base64url alphabet for indexed sig encoding. */
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode a 64-byte Ed25519 signature as an indexed CESR Siger qb64.
 * Code format: "A" + B64[index] = 2 chars, ls=2, raw=64 bytes → 88 chars total.
 * Encoding: prepend 2 zero bytes to 64-byte sig → 66 bytes → 88 B64 chars → replace first 2 with code.
 */
export function encodeIndexedSig(
  sigRaw: Uint8Array,
  index: number,
  ondex: number | null,
): IndexedSig {
  // Use cesr-ts Matter for encoding indexed sig
  // Code: "A" + B64[index]  (for both only=false case)
  // For only=true (ondex is null): code format differs but we use standard "A" + B64[idx]
  const codeChar = B64[index & 0x3f];
  const code = "A" + codeChar;

  // Encode: the sig is 64 bytes. For 2-char code with lead_size=2:
  // prepend 2 zero bytes → 66 bytes → 88 B64 chars
  // The code replaces first 2 chars.
  const padded = new Uint8Array(66);
  padded.set(sigRaw, 2); // 2 lead zero bytes
  const b64 = encodeB64Url(padded);
  const qb64 = code + b64.slice(2); // 2 + 86 = 88 chars

  return { index, ondex, raw: sigRaw.slice(), qb64 };
}

/** Base64url encode without padding. */
function encodeB64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += B64[((b1 & 0xf) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += B64[b2 & 0x3f];
  }
  return out;
}

/**
 * Create an EncryptedSecret from raw cipher bytes and a CESR code.
 * Uses cesr-ts Matter for proper CESR encoding.
 */
export function makeEncryptedSecretFromRaw(
  raw: Uint8Array,
  code: string,
): { raw: Uint8Array; code: string; qb64: string } {
  validateCipherCode(code, raw.length);
  const qb64 = matterEncode(raw, code);
  return { raw: raw.slice(), code, qb64 };
}

/**
 * Decode an EncryptedSecret from its qb64 string.
 */
export function encryptedSecretFromQb64(qb64: string): {
  raw: Uint8Array;
  code: string;
  qb64: string;
} {
  let code: string;
  if (qb64.startsWith("1AAH")) {
    code = "1AAH";
  } else if (qb64.startsWith("P")) {
    code = "P";
  } else {
    throw new DerivationError(`Unknown cipher code in qb64: ${qb64.slice(0, 4)}`);
  }
  const raw = matterDecode(qb64);
  return { raw, code, qb64 };
}

function validateCipherCode(code: string, rawLen: number): void {
  if (code === MtrDex.X25519_Cipher_Seed) {
    if (rawLen !== 92) {
      throw new DerivationError(
        `X25519_Cipher_Seed ("P") expects 92 raw bytes, got ${rawLen}`,
      );
    }
  } else if (code === MtrDex.X25519_Cipher_Salt) {
    if (rawLen !== 72) {
      throw new DerivationError(
        `X25519_Cipher_Salt ("1AAH") expects 72 raw bytes, got ${rawLen}`,
      );
    }
  } else {
    throw new DerivationError(`Unsupported cipher code: ${code}`);
  }
}
