/**
 * Minimal CESR (Composable Event Streaming Representation) codec.
 *
 * Handles T-domain (text/Base64) encoding and decoding of CESR primitives.
 * This is the harness's own ground truth -- independent of any KERI implementation.
 *
 * CESR alignment: every primitive is a multiple of 4 Base64 chars in T-domain
 * and a multiple of 3 bytes in B-domain (24-bit boundary).
 *
 * Reference: CESR spec §12 Master Code Table
 */

import { encodeB64, decodeB64, b64Value } from './base64url.js';

/**
 * Entry in the CESR Master Code Table.
 *
 * hs = hard size (code chars in T-domain)
 * ss = soft size (variable index/count chars in T-domain)
 * fs = full size (total T-domain chars, 0 = variable length)
 * rawSize = raw material bytes (excluding code)
 */
export interface CodeEntry {
  readonly code: string;
  readonly hs: number;
  readonly ss: number;
  readonly fs: number;
  readonly rawSize: number;
  readonly description: string;
}

/**
 * Subset of CESR Master Code Table v1 relevant for KEL verification.
 * Indexed by code string.
 */
export const CODE_TABLE: Record<string, CodeEntry> = {
  // 1-char codes (hs=1, ss=0, fs=44, raw=32)
  'A': { code: 'A', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'Ed25519 seed / raw 256-bit' },
  'B': { code: 'B', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'Ed25519 NT verfer' },
  'C': { code: 'C', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'X25519 NT cipher pubkey' },
  'D': { code: 'D', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'Ed25519 verfer' },
  'E': { code: 'E', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'Blake3-256 digest' },
  'F': { code: 'F', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'Blake2b-256 digest' },
  'G': { code: 'G', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'SHA3-256 digest' },
  'H': { code: 'H', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'SHA2-256 digest' },
  'I': { code: 'I', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'ECDSA secp256k1 NT verfer' },
  'J': { code: 'J', hs: 1, ss: 0, fs: 44, rawSize: 32, description: 'ECDSA secp256k1 digest' },
  'K': { code: 'K', hs: 1, ss: 0, fs: 76, rawSize: 56, description: 'Ed448 NT verfer' },
  'L': { code: 'L', hs: 1, ss: 0, fs: 76, rawSize: 56, description: 'Ed448 verfer' },
  'M': { code: 'M', hs: 1, ss: 0, fs: 4, rawSize: 2, description: 'Short value 2-byte' },
  'N': { code: 'N', hs: 1, ss: 0, fs: 12, rawSize: 8, description: 'Short number 8-byte' },

  // 2-char codes (hs=2, ss=0)
  '0A': { code: '0A', hs: 2, ss: 0, fs: 24, rawSize: 16, description: 'Random salt 128-bit' },
  '0B': { code: '0B', hs: 2, ss: 0, fs: 88, rawSize: 64, description: 'Ed25519 signature' },
  '0C': { code: '0C', hs: 2, ss: 0, fs: 88, rawSize: 64, description: 'ECDSA secp256k1 signature' },
  '0D': { code: '0D', hs: 2, ss: 0, fs: 88, rawSize: 64, description: 'SHA3-512 digest' },

  // 4-char codes (hs=4, ss=0)
  '1AAA': { code: '1AAA', hs: 4, ss: 0, fs: 48, rawSize: 33, description: 'ECDSA secp256k1 verfer' },
  '1AAB': { code: '1AAB', hs: 4, ss: 0, fs: 48, rawSize: 33, description: 'ECDSA secp256k1 NT verfer' },
  '1AAG': { code: '1AAG', hs: 4, ss: 0, fs: 36, rawSize: 24, description: 'DateTime' },
};

/**
 * A decoded CESR primitive: code entry + raw material bytes.
 */
export interface CesrPrimitive {
  readonly entry: CodeEntry;
  readonly raw: Uint8Array;
}

/**
 * Encode a CESR primitive to T-domain (Base64 text).
 *
 * The encoding is: code string + Base64(pad_bytes + raw_bytes),
 * where pad_bytes are leading zero bytes to achieve 24-bit alignment.
 *
 * For a primitive with code of hs chars and raw of rawSize bytes:
 *   total bytes = hs bytes (code as ASCII) + rawSize bytes
 *   But we need the total to be a multiple of 3 bytes for B-domain alignment.
 *   pad = (3 - ((hs + rawSize) % 3)) % 3  (but actually pad is built into fs)
 *
 * In practice: T-domain = code + Base64(zeros(pad) + raw), truncated to fs chars.
 * The number of pad bytes = fs * 3/4 - hs - rawSize
 * (where hs counts as raw bytes in B-domain because the code chars encode to those bytes).
 *
 * Simpler: CESR encodes by prepending the code, then encoding raw with enough
 * leading zeros so the total is fs Base64 chars.
 */
export function encodePrimitive(primitive: CesrPrimitive): string {
  const { entry, raw } = primitive;
  if (raw.length !== entry.rawSize) {
    throw new Error(`Raw size ${raw.length} does not match expected ${entry.rawSize} for code ${entry.code}`);
  }

  // Number of Base64 chars for the raw portion (after code)
  const rawB64Len = entry.fs - entry.hs - entry.ss;
  // Number of raw bytes that rawB64Len base64 chars decode to
  const totalRawBytes = (rawB64Len * 3) / 4;
  // Pad bytes = total - actual
  const padLen = totalRawBytes - raw.length;

  // Build padded raw: zeros + raw
  const padded = new Uint8Array(totalRawBytes);
  padded.set(raw, padLen);

  // Encode padded raw to Base64
  const rawB64 = encodeB64(padded);

  return entry.code + rawB64;
}

/**
 * Decode a CESR primitive from T-domain text.
 * Returns the primitive and the number of chars consumed.
 */
export function decodePrimitive(text: string, offset: number = 0): { primitive: CesrPrimitive; consumed: number } {
  const entry = lookupCode(text, offset);
  if (!entry) {
    throw new Error(`Unknown CESR code at offset ${offset}: "${text.substring(offset, offset + 4)}"`);
  }

  const fullText = text.substring(offset, offset + entry.fs);
  if (fullText.length < entry.fs) {
    throw new Error(`Insufficient data: need ${entry.fs} chars, have ${fullText.length}`);
  }

  // Extract the raw portion (after code + soft)
  const rawB64 = fullText.substring(entry.hs + entry.ss);
  const decoded = decodeB64(rawB64);

  // Strip leading pad bytes
  const padLen = decoded.length - entry.rawSize;
  const raw = decoded.slice(padLen);

  return {
    primitive: { entry, raw },
    consumed: entry.fs,
  };
}

/**
 * Look up a code entry from text at the given offset.
 * Tries 4-char, 2-char, then 1-char codes.
 */
function lookupCode(text: string, offset: number): CodeEntry | null {
  // 4-char codes start with '1'
  if (text[offset] === '1' && offset + 4 <= text.length) {
    const code4 = text.substring(offset, offset + 4);
    if (CODE_TABLE[code4]) return CODE_TABLE[code4];
  }

  // 2-char codes start with '0'
  if (text[offset] === '0' && offset + 2 <= text.length) {
    const code2 = text.substring(offset, offset + 2);
    if (CODE_TABLE[code2]) return CODE_TABLE[code2];
  }

  // 1-char codes
  const code1 = text[offset];
  if (CODE_TABLE[code1]) return CODE_TABLE[code1];

  return null;
}

/**
 * Decode a CESR stream (concatenated T-domain primitives) into an array.
 */
export function decodeStream(text: string): CesrPrimitive[] {
  const primitives: CesrPrimitive[] = [];
  let offset = 0;

  while (offset < text.length) {
    const { primitive, consumed } = decodePrimitive(text, offset);
    primitives.push(primitive);
    offset += consumed;
  }

  return primitives;
}

/**
 * Encode an array of CESR primitives into a concatenated T-domain stream.
 */
export function encodeStream(primitives: CesrPrimitive[]): string {
  return primitives.map(encodePrimitive).join('');
}
