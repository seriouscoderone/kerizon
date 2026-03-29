/**
 * Siger — indexed signature primitive.
 *
 * Unlike Matter-based primitives, Siger uses the Indexer code table (IdrDex/IdrSizage)
 * which includes an `os` (other index size) field. The `index` identifies the signing
 * key position, and `ondex` identifies the rotation/next key position.
 *
 * Encoding layout:
 *   qb64 = code + softChars(index [, ondex]) + B64(raw)
 *
 * For codes with os=0, ondex == index (implicit).
 * For codes with os>0, ondex is encoded separately.
 */

import { IdrDex, IdrSizage, type IndexedSizage } from './code-table.js';
import { encodeB64, decodeB64, b64Index, b64Value } from './matter.js';

// ---------------------------------------------------------------------------
// Code resolution for indexed signatures
// ---------------------------------------------------------------------------

const IDR_HS2_CHARS = new Set(['0', '1', '2', '3', '4']);

function resolveIdrCode(qb64: string): { code: string; sizage: IndexedSizage } {
  const first = qb64[0];

  // 2-char codes (first char is 0-4)
  if (IDR_HS2_CHARS.has(first) && qb64.length >= 2) {
    const c2 = qb64.substring(0, 2);
    if (IdrSizage[c2]) return { code: c2, sizage: IdrSizage[c2] };
  }

  // 1-char codes
  if (qb64.length >= 1) {
    const c1 = qb64[0];
    if (IdrSizage[c1]) return { code: c1, sizage: IdrSizage[c1] };
  }

  throw new Error(`Unknown Indexer code in qb64: "${qb64.substring(0, 4)}"`);
}

// ---------------------------------------------------------------------------
// Big-code promotion map: 1-char code → corresponding 2-char big code
// ---------------------------------------------------------------------------

const BIG_CODE_MAP: Record<string, string> = {
  [IdrDex.Ed25519_Sig]: IdrDex.Ed25519_Big_Sig,
  [IdrDex.Ed25519_Crt_Sig]: IdrDex.Ed25519_Big_Crt_Sig,
  [IdrDex.ECDSA_256k1_Sig]: IdrDex.ECDSA_256k1_Big_Sig,
  [IdrDex.ECDSA_256k1_Crt_Sig]: IdrDex.ECDSA_256k1_Big_Crt_Sig,
  [IdrDex.ECDSA_256r1_Sig]: IdrDex.ECDSA_256r1_Big_Sig,
  [IdrDex.ECDSA_256r1_Crt_Sig]: IdrDex.ECDSA_256r1_Big_Crt_Sig,
};

// ---------------------------------------------------------------------------
// Soft-value encoding/decoding helpers
// ---------------------------------------------------------------------------

/** Encode an integer into `n` B64 characters (big-endian). */
function encodeSoft(value: number, n: number): string {
  let result = '';
  for (let i = n - 1; i >= 0; i--) {
    result = b64Index((value >> (6 * i)) & 0x3f) + result;
  }
  // Build from least-significant to most-significant, reverse order
  let chars = '';
  let v = value;
  for (let i = 0; i < n; i++) {
    chars = b64Index(v & 0x3f) + chars;
    v = Math.floor(v / 64);
  }
  return chars;
}

/** Decode `n` B64 characters to an integer (big-endian). */
function decodeSoft(qb64: string, offset: number, n: number): number {
  let value = 0;
  for (let i = 0; i < n; i++) {
    value = value * 64 + b64Value(qb64[offset + i]);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Siger class
// ---------------------------------------------------------------------------

export interface SigerCreateOpts {
  raw: Uint8Array;
  index: number;
  ondex?: number;
  code?: string;
}

export class Siger {
  readonly code: string;
  readonly raw: Uint8Array;
  readonly index: number;
  readonly ondex: number;
  readonly qb64: string;

  private constructor(code: string, raw: Uint8Array, index: number, ondex: number, qb64: string) {
    this.code = code;
    this.raw = raw;
    this.index = index;
    this.ondex = ondex;
    this.qb64 = qb64;
  }

  /**
   * Create a Siger from raw signature bytes, index, and optional ondex.
   *
   * If `code` is not specified, defaults to 'A' (Ed25519_Sig).
   * Auto-promotes to big-index code if index > 63 and a 1-char code was given.
   */
  static create(opts: SigerCreateOpts): Siger {
    let { raw, index, ondex, code } = opts;

    // Default code
    if (!code) {
      code = IdrDex.Ed25519_Sig;
    }

    let sizage = IdrSizage[code];
    if (!sizage) {
      throw new Error(`Unknown Indexer code: "${code}"`);
    }

    // Auto-promote to big code if index doesn't fit in ss chars for 1-char codes
    if (sizage.os === 0 && sizage.ss === 1 && index > 63) {
      const bigCode = BIG_CODE_MAP[code];
      if (!bigCode) {
        throw new Error(`No big-index variant for code "${code}" with index ${index}`);
      }
      code = bigCode;
      sizage = IdrSizage[code]!;
    }

    // For os=0 codes, ondex is always equal to index
    if (sizage.os === 0) {
      ondex = index;
    } else if (ondex === undefined) {
      ondex = index;
    }

    // Encode to qb64
    const qb64 = Siger._infil(code, sizage, raw, index, ondex);

    return new Siger(code, new Uint8Array(raw), index, ondex, qb64);
  }

  /**
   * Decode a Siger from a qb64 string.
   */
  static fromQb64(qb64: string): Siger {
    const { code, sizage } = resolveIdrCode(qb64);

    if (qb64.length < sizage.fs) {
      throw new Error(
        `Insufficient qb64 length: need ${sizage.fs}, got ${qb64.length} for Indexer code "${code}"`,
      );
    }

    const full = qb64.substring(0, sizage.fs);

    // Decode index and ondex from soft chars
    const indexChars = sizage.ss - sizage.os;
    const index = decodeSoft(full, sizage.hs, indexChars);
    let ondex: number;

    if (sizage.os === 0) {
      ondex = index;
    } else {
      ondex = decodeSoft(full, sizage.hs + indexChars, sizage.os);
    }

    // Decode full B-domain bytes (replace code+soft with zero padding)
    const zeroPad = 'A'.repeat(sizage.hs + sizage.ss);
    const fullB64 = zeroPad + full.substring(sizage.hs + sizage.ss);
    const fullBytes = decodeB64(fullB64);

    // Raw is right-aligned. Total bytes = fs*3/4.
    // Pad bytes = total - raw. We know raw size from the sig algorithm:
    // For Ed25519 (64 bytes), ECDSA (64 bytes), Ed448 (114 bytes).
    const totalBytes = (sizage.fs * 3) / 4;
    // Raw size = totalBytes - leading pad (which includes ls + alignment pad)
    // Simplest: same formula as Matter. fs chars encode totalBytes bytes.
    // The code+soft region occupies (hs+ss)*6 bits in the B-domain.
    // The raw starts after the pad. We know pad = totalBytes - rawSize.
    // rawSize for sigs: Ed25519=64, ECDSA=64, Ed448=114.
    // Formula: rawSize = totalBytes - ls - floor((hs+ss)*6/8)... no, simpler:
    // rawSize = totalBytes - (totalBytes - floor((fs - hs - ss) * 3/4)) - ls
    // = floor((fs - hs - ss) * 3/4) - ls
    const rawSize = Math.floor(((sizage.fs - sizage.hs - sizage.ss) * 3) / 4) - sizage.ls;
    const raw = fullBytes.slice(fullBytes.length - rawSize);

    return new Siger(code, raw, index, ondex, full);
  }

  /**
   * Encode to qb64.
   *
   * Like Matter, the entire qb64 is a contiguous B64 stream.
   * The code + soft chars replace the first (hs+ss) chars of
   * the full B64 encoding.
   */
  private static _infil(
    code: string,
    sizage: IndexedSizage,
    raw: Uint8Array,
    index: number,
    ondex: number,
  ): string {
    // Build soft chars: index chars + ondex chars (if os > 0)
    const indexChars = sizage.ss - sizage.os;
    let soft = encodeSoft(index, indexChars);
    if (sizage.os > 0) {
      soft += encodeSoft(ondex, sizage.os);
    }

    // Encode full buffer: total bytes = fs * 3 / 4, raw right-aligned
    const totalBytes = (sizage.fs * 3) / 4;
    const padLen = totalBytes - raw.length;
    const full = new Uint8Array(totalBytes);
    full.set(raw, padLen);

    const fullB64 = encodeB64(full);

    // Replace first (hs + ss) chars with code + soft
    return code + soft + fullB64.substring(sizage.hs + sizage.ss);
  }
}
