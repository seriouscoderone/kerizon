import { Kever } from '../state/kever.js';
import type { Serder } from '@kerizon/cesr';
import type { ProcessResult } from './types.js';

export interface KeverStore {
  get(prefix: string): Kever | undefined;
  set(prefix: string, kever: Kever): void;
  getLastSaid(prefix: string): string | undefined;
  getExpectedSn(prefix: string): number;
}

export function processEvent(
  serder: Serder,
  store: KeverStore,
): ProcessResult {
  const prefix = serder.pre;
  const sn = serder.sn;
  const ilk = serder.ilk;
  const kever = store.get(prefix);

  // Case 1: Unknown prefix
  if (!kever) {
    if (ilk === 'icp' || ilk === 'dip') {
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
