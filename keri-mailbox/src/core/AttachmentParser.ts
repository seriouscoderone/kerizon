import { parseIndexerFromText, parseMatterFromText } from "cesr-ts";
import type { AttachmentGroup } from "cesr-ts";

/** One indexed signature from a ControllerIdxSigs or WitnessIdxSigs group. */
export interface IndexedSig {
  /** Zero-based index into the current keys array. */
  index: number;
  /** Raw signature bytes (64 bytes for Ed25519). */
  raw: Uint8Array;
  /** Full qb64 representation. */
  qb64: string;
}

/** One non-transferable receipt couple (verfer + cigar). */
export interface CoupledSig {
  /** qb64-encoded public key (verfer). */
  verferQb64: string;
  /** Raw public key bytes. */
  verferRaw: Uint8Array;
  /** Raw signature bytes. */
  sigRaw: Uint8Array;
  /** qb64-encoded signature (cigar). */
  sigQb64: string;
}

/** Typed signatures extracted from CESR attachment groups. */
export interface ParsedAttachments {
  /** Indexed signatures from ControllerIdxSigs / WitnessIdxSigs groups. */
  indexedSigs: IndexedSig[];
  /** Non-indexed receipt couples from NonTransReceiptCouples groups. */
  coupledSigs: CoupledSig[];
}

/** CESR base64 alphabet for index decoding. */
const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64CharToInt(ch: string): number {
  const idx = B64_ALPHABET.indexOf(ch);
  if (idx < 0) throw new Error(`Invalid CESR base64 char: '${ch}'`);
  return idx;
}

/**
 * Extract the key index from an indexed-signature qb64 string.
 * For single-char hard codes (hs=1), the soft part starts at position 1.
 */
function indexFromIndexerQb64(qb64: string): number {
  if (qb64.length < 2) throw new Error("Indexer qb64 too short");
  return b64CharToInt(qb64[1]);
}

/**
 * Walk CESR attachment groups and extract typed signatures.
 *
 * Handles:
 *   - ControllerIdxSigs  (-A group): indexed signatures
 *   - WitnessIdxSigs     (-B group): indexed signatures
 *   - NonTransReceiptCouples: (verfer, cigar) couples
 */
export function parseAttachments(groups: AttachmentGroup[]): ParsedAttachments {
  const indexedSigs: IndexedSig[] = [];
  const coupledSigs: CoupledSig[] = [];

  for (const group of groups) {
    const { name, items } = group;

    if (name === "ControllerIdxSigs" || name === "WitnessIdxSigs") {
      for (const item of items) {
        if (item.kind !== "tuple") continue;
        const sigItem = item.items[0];
        if (!sigItem || sigItem.kind !== "qb64") continue;
        const encoded = new TextEncoder().encode(sigItem.qb64);
        try {
          const indexer = parseIndexerFromText(encoded);
          indexedSigs.push({
            index: indexFromIndexerQb64(indexer.qb64),
            raw: indexer.raw,
            qb64: indexer.qb64,
          });
        } catch {
          // skip malformed indexer
        }
      }
    } else if (name === "NonTransReceiptCouples") {
      for (const item of items) {
        if (item.kind !== "tuple") continue;
        const [verferItem, cigarItem] = item.items;
        if (
          !verferItem ||
          verferItem.kind !== "qb64" ||
          !cigarItem ||
          cigarItem.kind !== "qb64"
        )
          continue;
        try {
          const verfer = parseMatterFromText(
            new TextEncoder().encode(verferItem.qb64),
          );
          const cigar = parseMatterFromText(
            new TextEncoder().encode(cigarItem.qb64),
          );
          coupledSigs.push({
            verferQb64: verfer.qb64,
            verferRaw: verfer.raw,
            sigRaw: cigar.raw,
            sigQb64: cigar.qb64,
          });
        } catch {
          // skip malformed couple
        }
      }
    }
  }

  return { indexedSigs, coupledSigs };
}
