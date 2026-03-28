/**
 * URL-safe Base64 encoding/decoding without padding.
 * CESR uses this alphabet: A-Z a-z 0-9 -_
 */

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const DECODE_TABLE = new Uint8Array(128);
DECODE_TABLE.fill(255);
for (let i = 0; i < B64_CHARS.length; i++) {
  DECODE_TABLE[B64_CHARS.charCodeAt(i)] = i;
}

/** Encode raw bytes to URL-safe Base64 without padding. */
export function encodeB64(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  let i = 0;

  while (i + 2 < len) {
    const a = bytes[i++];
    const b = bytes[i++];
    const c = bytes[i++];
    result += B64_CHARS[(a >> 2) & 0x3f];
    result += B64_CHARS[((a << 4) | (b >> 4)) & 0x3f];
    result += B64_CHARS[((b << 2) | (c >> 6)) & 0x3f];
    result += B64_CHARS[c & 0x3f];
  }

  if (i + 1 === len) {
    const a = bytes[i++];
    result += B64_CHARS[(a >> 2) & 0x3f];
    result += B64_CHARS[(a << 4) & 0x3f];
  } else if (i + 2 === len) {
    const a = bytes[i++];
    const b = bytes[i++];
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
    const a = DECODE_TABLE[str.charCodeAt(i)];
    const b = i + 1 < len ? DECODE_TABLE[str.charCodeAt(i + 1)] : 0;
    const c = i + 2 < len ? DECODE_TABLE[str.charCodeAt(i + 2)] : 0;
    const d = i + 3 < len ? DECODE_TABLE[str.charCodeAt(i + 3)] : 0;

    out[j++] = ((a << 2) | (b >> 4)) & 0xff;
    if (j < outLen) out[j++] = ((b << 4) | (c >> 2)) & 0xff;
    if (j < outLen) out[j++] = ((c << 6) | d) & 0xff;
  }

  return out;
}

/** Convert a 6-bit index (0-63) to its Base64 character. */
export function b64Index(i: number): string {
  return B64_CHARS[i & 0x3f];
}

/** Convert a Base64 character to its 6-bit index. */
export function b64Value(ch: string): number {
  return DECODE_TABLE[ch.charCodeAt(0)];
}
