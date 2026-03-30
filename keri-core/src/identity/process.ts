import { Kever } from '../state/kever.js';
import type { Serder, Siger } from '@kerizon/cesr';
import type { ProcessResult } from './types.js';
import { verifySignatures } from '../establishment/verify-sigs.js';

export interface KeverStore {
  get(prefix: string): Kever | undefined;
  set(prefix: string, kever: Kever): void;
  getLastSaid(prefix: string): string | undefined;
  getExpectedSn(prefix: string): number;
}

/**
 * Process a KERI event against the key state store.
 *
 * When `sigers` are provided, cryptographic signature verification is
 * performed before the event is accepted. For inception/delegated inception
 * events, signatures are verified against the keys declared in the event
 * itself (`ked.k`). For all other events, signatures are verified against
 * the current key state in the Kever.
 *
 * If `sigers` is omitted, signature verification is skipped (backward
 * compatible with callers that perform verification externally).
 */
export async function processEvent(
  serder: Serder,
  store: KeverStore,
  sigers?: Siger[],
): Promise<ProcessResult> {
  const prefix = serder.pre;
  const sn = serder.sn;
  const ilk = serder.ilk;
  const kever = store.get(prefix);

  // Case 1: Unknown prefix
  if (!kever) {
    if (ilk === 'icp' || ilk === 'dip') {
      // Verify signatures against keys declared in the inception event
      if (sigers && sigers.length > 0) {
        const keys = serder.ked['k'] as string[];
        const threshold = serder.ked['kt'] as string;
        const sigResult = await verifySignatures(serder.raw, sigers, keys, threshold);
        if (!sigResult.verified) {
          return { status: 'rejected', reason: sigResult.reason! };
        }
      }

      const newKever = Kever.fromInception(serder);
      store.set(prefix, newKever);
      return { status: 'accepted', aid: prefix, sn: 0, said: serder.said };
    }
    return { status: 'escrowed', escrowType: 'OOE', aid: prefix, sn, reason: 'unknown prefix, not inception' };
  }

  const expectedSn = kever.sn + 1;

  // Case 2: Out of order (future)
  if (sn > expectedSn) {
    return { status: 'escrowed', escrowType: 'OOE', aid: prefix, sn, reason: `expected sn=${expectedSn}, got sn=${sn}` };
  }

  // Case 3: Already seen
  if (sn < expectedSn) {
    return { status: 'duplicate', aid: prefix, sn };
  }

  // Case 4: Non-transferable rejects rotation
  if ((ilk === 'rot' || ilk === 'drt') && !kever.transferable) {
    return { status: 'rejected', reason: 'non-transferable identifier: rotation not allowed' };
  }

  // Verify signatures against current key state
  if (sigers && sigers.length > 0) {
    const sigResult = await verifySignatures(
      serder.raw,
      sigers,
      kever.currentKeys,
      kever.signingThreshold,
    );
    if (!sigResult.verified) {
      return { status: 'rejected', reason: sigResult.reason! };
    }
  }

  // Case 5: Expected sn -- process
  try {
    let updated: Kever;
    if (ilk === 'rot' || ilk === 'drt') {
      updated = kever.applyEstablishment(serder);
    } else if (ilk === 'ixn') {
      updated = kever.applyInteraction(serder);
    } else {
      return { status: 'rejected', reason: `unexpected ilk: ${ilk}` };
    }
    store.set(prefix, updated);
    return { status: 'accepted', aid: prefix, sn, said: serder.said };
  } catch (err: unknown) {
    return { status: 'rejected', reason: err instanceof Error ? err.message : String(err) };
  }
}
