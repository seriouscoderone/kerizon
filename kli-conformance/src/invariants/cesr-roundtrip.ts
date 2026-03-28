/**
 * CESR Round-Trip Invariant:
 *
 * Property: For any CESR primitive P:
 *   decode(encode(P)) ≡ P        (raw bytes preserved)
 *   encode(decode(encode(P))) ≡ encode(P)  (text idempotent)
 *
 * And for streams:
 *   decodeStream(encodeStream(Ps)) ≡ Ps
 */

import fc from 'fast-check';
import {
  encodePrimitive,
  decodePrimitive,
  encodeStream,
  decodeStream,
  type CesrPrimitive,
} from '../util/cesr-codec.js';
import { arbCesrPrimitive, arbCesrStream } from '../generators/cesr.js';

/** Helper: compare two Uint8Arrays for equality. */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Property: encode then decode preserves raw bytes and code. */
export const singlePrimitiveRoundTrip = fc.property(
  arbCesrPrimitive,
  (primitive: CesrPrimitive) => {
    const encoded = encodePrimitive(primitive);

    // Verify T-domain length matches code table
    if (encoded.length !== primitive.entry.fs) return false;

    // Verify code prefix
    if (!encoded.startsWith(primitive.entry.code)) return false;

    // Decode and compare
    const { primitive: decoded, consumed } = decodePrimitive(encoded);
    if (consumed !== encoded.length) return false;
    if (decoded.entry.code !== primitive.entry.code) return false;
    if (!arraysEqual(decoded.raw, primitive.raw)) return false;

    return true;
  },
);

/** Property: encode → decode → encode is idempotent. */
export const encodeIdempotent = fc.property(
  arbCesrPrimitive,
  (primitive: CesrPrimitive) => {
    const first = encodePrimitive(primitive);
    const { primitive: decoded } = decodePrimitive(first);
    const second = encodePrimitive(decoded);
    return first === second;
  },
);

/** Property: stream encode → decode → encode round-trips. */
export const streamRoundTrip = fc.property(
  arbCesrStream(1, 20),
  (primitives: CesrPrimitive[]) => {
    const encoded = encodeStream(primitives);
    const decoded = decodeStream(encoded);

    if (decoded.length !== primitives.length) return false;

    for (let i = 0; i < primitives.length; i++) {
      if (decoded[i].entry.code !== primitives[i].entry.code) return false;
      if (!arraysEqual(decoded[i].raw, primitives[i].raw)) return false;
    }

    // Re-encode must match
    const reencoded = encodeStream(decoded);
    return encoded === reencoded;
  },
);
