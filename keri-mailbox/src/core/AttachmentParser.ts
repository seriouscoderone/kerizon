import { Indexer, Matter, isPrimitiveTuple } from "cesr-ts";
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
        if (!isPrimitiveTuple(item)) continue;
        const indexer = item[0];
        if (!(indexer instanceof Indexer)) continue;
        indexedSigs.push({
          index: indexer.index,
          raw: indexer.raw,
          qb64: indexer.qb64,
        });
      }
    } else if (name === "NonTransReceiptCouples") {
      for (const item of items) {
        if (!isPrimitiveTuple(item)) continue;
        const [verfer, cigar] = item;
        if (!(verfer instanceof Matter) || !(cigar instanceof Matter)) continue;
        coupledSigs.push({
          verferQb64: verfer.qb64,
          verferRaw: verfer.raw,
          sigRaw: cigar.raw,
          sigQb64: cigar.qb64,
        });
      }
    }
  }

  return { indexedSigs, coupledSigs };
}
