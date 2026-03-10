/**
 * SigningKey — a wrapper around an Ed25519 seed that can produce
 * indexed (Siger) and unindexed (Cigar) signatures.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { parseMatterFromText } from "cesr-ts";
import {
  MtrDex,
  matterEncode,
  makeVerfer,
  encodeIndexedSig,
  type Verfer,
  type IndexedSig,
  type UnindexedSig,
} from "./cesr-helpers.js";

/** A full Ed25519 signing key with verfer. */
export interface SigningKey {
  /** 32-byte raw seed */
  raw: Uint8Array;
  /** CESR code — always "A" (Ed25519_Seed) */
  code: string;
  /** qb64 of the seed */
  qb64: string;
  /** qb64 bytes of the seed */
  qb64b: Uint8Array;
  /** Corresponding public verification key */
  verfer: Verfer;
  /** Whether this key is transferable */
  transferable: boolean;
  /**
   * Sign a serialization.
   * @param ser - The bytes to sign
   * @param indexed - True = return IndexedSig, false = return UnindexedSig
   * @param index - Signing key index (for indexed sigs)
   * @param ondex - Pre-rotation index (null means same as index)
   */
  sign(
    ser: Uint8Array,
    indexed: boolean,
    index?: number,
    ondex?: number | null,
  ): IndexedSig | UnindexedSig;
}

/**
 * Create a SigningKey from a 32-byte raw seed.
 */
export function makeSigningKey(raw: Uint8Array, transferable: boolean): SigningKey {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${raw.length}`);
  }
  const seedRaw = raw.slice();
  const pubKeyRaw = ed25519.getPublicKey(seedRaw);
  const verfer = makeVerfer(pubKeyRaw, transferable);
  const qb64 = matterEncode(seedRaw, MtrDex.Ed25519_Seed);
  const qb64b = new TextEncoder().encode(qb64);

  return {
    raw: seedRaw,
    code: MtrDex.Ed25519_Seed,
    qb64,
    qb64b,
    verfer,
    transferable,
    sign(
      ser: Uint8Array,
      indexed: boolean,
      index = 0,
      ondex: number | null = null,
    ): IndexedSig | UnindexedSig {
      const sigBytes = ed25519.sign(ser, seedRaw);
      if (indexed) {
        return encodeIndexedSig(sigBytes, index, ondex);
      } else {
        return {
          raw: sigBytes,
          verferQb64: verfer.qb64,
        } as UnindexedSig;
      }
    },
  };
}

/**
 * Reconstruct a SigningKey from a qb64 seed string.
 */
export function signingKeyFromQb64(qb64: string, transferable = true): SigningKey {
  const encoded = new TextEncoder().encode(qb64);
  const matter = parseMatterFromText(encoded);
  return makeSigningKey(matter.raw, transferable);
}
