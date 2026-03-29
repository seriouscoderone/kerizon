import { Serder } from '@kerizon/cesr';
import type { InteractConfig } from './types.js';
import { IXN_FIELDS } from './types.js';

/**
 * Create an interaction event (ixn).
 *
 * Builds the KED with fields in canonical IXN_FIELDS order and delegates to
 * Serder.fromKed() for version string generation and SAID computation.
 */
export function interact(config: InteractConfig): Serder {
  const ked: Record<string, unknown> = {};

  for (const field of IXN_FIELDS) {
    switch (field) {
      case 'v': ked['v'] = ''; break;
      case 't': ked['t'] = 'ixn'; break;
      case 'd': ked['d'] = ''; break;
      case 'i': ked['i'] = config.prefix; break;
      case 's': ked['s'] = config.sn.toString(16); break;
      case 'p': ked['p'] = config.priorDigest; break;
      case 'a': ked['a'] = config.data ?? []; break;
    }
  }

  return Serder.fromKed(ked);
}
