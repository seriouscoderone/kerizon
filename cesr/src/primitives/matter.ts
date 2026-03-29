/**
 * Matter — the foundational CESR primitive type.
 *
 * All typed CESR primitives (Verfer, Diger, Signer, etc.) extend Matter.
 * A Matter value holds a code (from the Master Code Table) and raw material bytes,
 * and can convert between T-domain (qb64) and B-domain (qb2) representations.
 */

import { MtrSizage, type Sizage } from './code-table.js';

// ---------------------------------------------------------------------------
// URL-safe Base64 (CESR alphabet: A-Za-z0-9-_)
// ---------------------------------------------------------------------------

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const B64_DECODE = new Uint8Array(128);
B64_DECODE.fill(0xff);
for (let i = 0; i < B64_CHARS.length; i++) {
  B64_DECODE[B64_CHARS.charCodeAt(i)] = i;
}

/** Encode raw bytes to URL-safe Base64 without padding. */
export function encodeB64(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  let i = 0;

  // Full 3-byte groups → 4 B64 chars each
  while (i + 2 < len) {
    const a = bytes[i++];
    const b = bytes[i++];
    const c = bytes[i++];
    result += B64_CHARS[(a >> 2) & 0x3f];
    result += B64_CHARS[((a << 4) | (b >> 4)) & 0x3f];
    result += B64_CHARS[((b << 2) | (c >> 6)) & 0x3f];
    result += B64_CHARS[c & 0x3f];
  }

  // Trailing 1 byte → 2 B64 chars
  if (i + 1 === len) {
    const a = bytes[i];
    result += B64_CHARS[(a >> 2) & 0x3f];
    result += B64_CHARS[(a << 4) & 0x3f];
  }
  // Trailing 2 bytes → 3 B64 chars
  else if (i + 2 === len) {
    const a = bytes[i];
    const b = bytes[i + 1];
    result += B64_CHARS[(a >> 2) & 0x3f];
    result += B64_CHARS[((a << 4) | (b >> 4)) & 0x3f];
    result += B64_CHARS[(b << 2) & 0x3f];
  }

  return result;
}

/** Decode URL-safe Base64 (no padding) to raw bytes. */
export function decodeB64(str: string): Uint8Array {
  const len = str.length;
  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);
  let j = 0;

  for (let i = 0; i < len; i += 4) {
    const a = B64_DECODE[str.charCodeAt(i)];
    const b = i + 1 < len ? B64_DECODE[str.charCodeAt(i + 1)] : 0;
    const c = i + 2 < len ? B64_DECODE[str.charCodeAt(i + 2)] : 0;
    const d = i + 3 < len ? B64_DECODE[str.charCodeAt(i + 3)] : 0;

    out[j++] = ((a << 2) | (b >> 4)) & 0xff;
    if (j < outLen) out[j++] = ((b << 4) | (c >> 2)) & 0xff;
    if (j < outLen) out[j++] = ((c << 6) | d) & 0xff;
  }

  return out;
}

/** Convert a 6-bit index to its B64 character. */
export function b64Index(i: number): string {
  return B64_CHARS[i & 0x3f];
}

/** Convert a B64 character to its 6-bit index. */
export function b64Value(ch: string): number {
  return B64_DECODE[ch.charCodeAt(0)];
}

// ---------------------------------------------------------------------------
// Code resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the Matter code from a qb64 string.
 * Tries 4-char, 2-char, then 1-char codes in that order.
 */
export function resolveCode(qb64: string): { code: string; sizage: Sizage } {
  // 4-char codes start with '1'
  if (qb64[0] === '1' && qb64.length >= 4) {
    const c4 = qb64.substring(0, 4);
    if (MtrSizage[c4]) return { code: c4, sizage: MtrSizage[c4] };
  }

  // 2-char codes start with '0'
  if (qb64[0] === '0' && qb64.length >= 2) {
    const c2 = qb64.substring(0, 2);
    if (MtrSizage[c2]) return { code: c2, sizage: MtrSizage[c2] };
  }

  // 1-char codes
  if (qb64.length >= 1) {
    const c1 = qb64[0];
    if (MtrSizage[c1]) return { code: c1, sizage: MtrSizage[c1] };
  }

  throw new Error(`Unknown CESR code in qb64: "${qb64.substring(0, 4)}"`);
}

/**
 * Compute the expected raw material byte count for a given sizage.
 *
 * value_b64_chars = fs - hs - ss
 * raw_bytes = floor(value_b64_chars * 3 / 4) - ls
 */
export function rawSizeFromSizage(sizage: Sizage): number {
  const valueChars = sizage.fs - sizage.hs - sizage.ss;
  return Math.floor((valueChars * 3) / 4) - sizage.ls;
}

// ---------------------------------------------------------------------------
// Matter class
// ---------------------------------------------------------------------------

export type MatterArgs =
  | { code: string; raw: Uint8Array; qb64?: undefined }
  | { qb64: string; code?: undefined; raw?: undefined };

/**
 * Matter — base CESR primitive.
 *
 * Constructed from either `{ code, raw }` (encode) or `{ qb64 }` (decode).
 * Immutable once created.
 */
export class Matter {
  readonly code: string;
  readonly raw: Uint8Array;

  private _qb64: string | null = null;
  private _qb2: Uint8Array | null = null;

  constructor(args: MatterArgs) {
    if (args.qb64 !== undefined) {
      // Decode path
      const qb64 = args.qb64;
      if (qb64.length === 0) {
        throw new Error('Empty qb64 string');
      }
      const { code, sizage } = resolveCode(qb64);
      if (qb64.length < sizage.fs) {
        throw new Error(
          `Insufficient qb64 length: need ${sizage.fs}, got ${qb64.length} for code "${code}"`,
        );
      }

      this.code = code;
      this._qb64 = qb64.substring(0, sizage.fs);

      // Decode the value portion
      const valueB64 = this._qb64.substring(sizage.hs + sizage.ss);
      const decoded = decodeB64(valueB64);

      // Strip leading pad bytes
      const expectedRaw = rawSizeFromSizage(sizage);
      const padLen = decoded.length - expectedRaw;
      this.raw = decoded.slice(padLen);
    } else {
      // Encode path
      const { code, raw } = args;
      const sizage = MtrSizage[code];
      if (!sizage) {
        throw new Error(`Unknown Matter code: "${code}"`);
      }

      const expectedRaw = rawSizeFromSizage(sizage);
      if (raw.length !== expectedRaw) {
        throw new Error(
          `Raw size mismatch for code "${code}": expected ${expectedRaw} bytes, got ${raw.length}`,
        );
      }

      this.code = code;
      // Copy so external mutations don't affect us
      this.raw = new Uint8Array(raw);
    }
  }

  /** Qualified Base64 representation (T-domain). */
  get qb64(): string {
    if (this._qb64 === null) {
      this._qb64 = this._infil();
    }
    return this._qb64;
  }

  /** Qualified binary representation (B-domain). */
  get qb2(): Uint8Array {
    if (this._qb2 === null) {
      this._qb2 = decodeB64(this.qb64);
    }
    return this._qb2;
  }

  /**
   * Encode to T-domain qb64 string.
   *
   * Algorithm:
   *   1. Compute padded raw: prepend ls lead bytes + enough zeros for alignment
   *   2. Encode padded raw to B64
   *   3. Prepend code string
   */
  private _infil(): string {
    const sizage = MtrSizage[this.code];
    if (!sizage) {
      throw new Error(`Unknown code during encoding: "${this.code}"`);
    }

    const valueChars = sizage.fs - sizage.hs - sizage.ss;
    const totalValueBytes = Math.floor((valueChars * 3) / 4);
    const padLen = totalValueBytes - this.raw.length;

    // Build padded raw: [0]*padLen + raw
    const padded = new Uint8Array(totalValueBytes);
    padded.set(this.raw, padLen);

    // Encode to B64 and prepend code
    const valueB64 = encodeB64(padded);
    return this.code + valueB64;
  }
}
