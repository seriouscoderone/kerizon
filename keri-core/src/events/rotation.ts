import { Serder } from '@kerizon/cesr';
import type { RotateConfig } from './types.js';
import { ROT_FIELDS } from './types.js';

/**
 * Create a rotation event (rot).
 *
 * Builds the KED with fields in canonical ROT_FIELDS order and delegates to
 * Serder.fromKed() for version string generation and SAID computation.
 */
export function rotate(config: RotateConfig): Serder {
  const ked: Record<string, unknown> = {};

  for (const field of ROT_FIELDS) {
    switch (field) {
      case 'v': ked['v'] = ''; break;
      case 't': ked['t'] = 'rot'; break;
      case 'd': ked['d'] = ''; break;
      case 'i': ked['i'] = config.prefix; break;
      case 's': ked['s'] = config.sn.toString(16); break;
      case 'p': ked['p'] = config.priorDigest; break;
      case 'kt': ked['kt'] = config.signingThreshold ?? '1'; break;
      case 'k': ked['k'] = config.keys; break;
      case 'nt': ked['nt'] = config.nextThreshold ?? '1'; break;
      case 'n': ked['n'] = config.nextDigests; break;
      case 'bt': ked['bt'] = (config.witnessThreshold ?? 0).toString(16); break;
      case 'br': ked['br'] = config.witnessesToRemove ?? []; break;
      case 'ba': ked['ba'] = config.witnessesToAdd ?? []; break;
      case 'c': ked['c'] = []; break;
      case 'a': ked['a'] = config.data ?? []; break;
    }
  }

  return Serder.fromKed(ked);
}
