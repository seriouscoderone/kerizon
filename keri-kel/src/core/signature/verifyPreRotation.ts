import type { ICryptoProvider } from "../../interfaces/ICryptoProvider.js";
import { publicKeyBytesFromQb64 } from "./verifySigs.js";

/**
 * Verify pre-rotation commitments for a rotation event.
 *
 * During rotation, each signer must prove they control a key that was
 * pre-committed in the prior establishment event's next-key digest list.
 *
 * For each verified siger:
 * 1. current_verfer = current_keys[siger.index] (from this event's k field)
 * 2. committed_diger = prior_next_digests[siger.ondex] (from prior est event's n field)
 * 3. Compute digest of current_verfer.qb64 using the committed digest's algorithm
 * 4. Verify digest matches committed_diger
 *
 * @param crypto - Crypto provider for digest computation
 * @param currentKeys - Current signing keys (qb64) from this rotation event's `k` field
 * @param priorNextDigests - Next key digests (qb64) from prior establishment event's `n` field
 * @param verifiedSigers - Verified sigers with index and ondex
 * @returns List of indices that satisfy the pre-rotation commitment
 */
export async function verifyPreRotation(
  crypto: ICryptoProvider,
  currentKeys: string[],
  priorNextDigests: string[],
  verifiedSigers: Array<{ index: number; ondex?: number }>,
): Promise<number[]> {
  const satisfiedIndices: number[] = [];

  for (const siger of verifiedSigers) {
    const ondex = siger.ondex ?? siger.index;
    if (ondex >= priorNextDigests.length) continue;
    if (siger.index >= currentKeys.length) continue;

    const verferQb64 = currentKeys[siger.index];
    const committedDigestQb64 = priorNextDigests[ondex];

    // Parse the committed digest to determine algorithm and expected bytes
    const committedRaw = publicKeyBytesFromQb64(committedDigestQb64);

    // Compute the digest of the current verfer's qb64 bytes
    const verferBytes = new TextEncoder().encode(verferQb64);
    const computedDigest = await crypto.digest(verferBytes);

    // Compare computed digest with committed digest
    if (
      computedDigest.length === committedRaw.length &&
      computedDigest.every((b, i) => b === committedRaw[i])
    ) {
      satisfiedIndices.push(siger.index);
    }
  }

  return satisfiedIndices;
}
