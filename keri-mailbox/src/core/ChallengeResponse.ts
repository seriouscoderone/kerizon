import { parseIndexerFromText, parseMatterFromText } from "cesr-ts";
import type { KeyState } from "../types/KeyState.js";
import { evaluateThreshold } from "./ThresholdEvaluator.js";

/** CESR base64 alphabet for nonce encoding. */
const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Generate a cryptographically random 128-bit nonce encoded as CESR base64url.
 * Returns 22 characters (ceiling of 128/6 bits per base64 char).
 */
export function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    result += B64_ALPHABET[(b0 >> 2) & 0x3f];
    result += B64_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3f];
    result += B64_ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3f];
    result += B64_ALPHABET[b2 & 0x3f];
  }
  return result.slice(0, 22);
}

/**
 * Verify a challenge-response signature.
 *
 * @param nonce - The challenge nonce string (from generateNonce()).
 * @param sigQb64 - The signature encoded as a qb64 Indexer or Matter string.
 * @param keyState - The key state of the expected signer.
 * @returns true if the signature satisfies the key state threshold.
 */
export async function verifyResponse(
  nonce: string,
  sigQb64: string,
  keyState: KeyState,
): Promise<boolean> {
  const message = new TextEncoder().encode(nonce);
  const encoded = new TextEncoder().encode(sigQb64);

  // Try to parse as Indexer first (common for KERI signatures), then as Matter
  let sigRaw: Uint8Array;
  let index = 0;

  try {
    const indexer = parseIndexerFromText(encoded);
    sigRaw = indexer.raw;
    // Decode index from soft part (position 1 for single-char hard codes)
    const b64Idx = B64_ALPHABET.indexOf(sigQb64[1]);
    index = b64Idx >= 0 ? b64Idx : 0;
  } catch {
    try {
      const matter = parseMatterFromText(encoded);
      sigRaw = matter.raw;
      index = 0;
    } catch {
      return false;
    }
  }

  return evaluateThreshold({
    indexedSigs: [{ index, raw: sigRaw, qb64: sigQb64 }],
    coupledSigs: [],
    message,
    keyState,
  });
}
