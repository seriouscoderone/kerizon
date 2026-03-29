import { Serder } from '@kerizon/cesr';
import type { InceptConfig } from './types.js';
import { ICP_FIELDS, DIP_FIELDS } from './types.js';

/**
 * Create an inception event (icp or dip if delegator is present).
 *
 * Builds the KED with fields in canonical order and delegates to
 * Serder.fromKed() for version string generation and SAID computation.
 */
export function incept(config: InceptConfig): Serder {
  const isDelegated = config.delegator !== undefined;
  const eventType = isDelegated ? 'dip' : 'icp';

  const ked: Record<string, unknown> = {};

  // Build in canonical field order
  const fields = isDelegated ? DIP_FIELDS : ICP_FIELDS;
  for (const field of fields) {
    switch (field) {
      case 'v': ked['v'] = ''; break;        // placeholder, Serder fills it
      case 't': ked['t'] = eventType; break;
      case 'd': ked['d'] = ''; break;        // placeholder, Serder fills it
      case 'i': ked['i'] = ''; break;        // placeholder, Serder fills it (inception: i === d)
      case 's': ked['s'] = '0'; break;       // always 0 for inception
      case 'kt': ked['kt'] = config.signingThreshold ?? '1'; break;
      case 'k': ked['k'] = config.keys; break;
      case 'nt': ked['nt'] = config.nextThreshold ?? '1'; break;
      case 'n': ked['n'] = config.nextDigests; break;
      case 'bt': ked['bt'] = (config.witnessThreshold ?? 0).toString(16); break;
      case 'b': ked['b'] = config.witnesses ?? []; break;
      case 'c': ked['c'] = config.configTraits ?? []; break;
      case 'a': ked['a'] = config.data ?? []; break;
      case 'di': ked['di'] = config.delegator!; break;
    }
  }

  return Serder.fromKed(ked);
}
