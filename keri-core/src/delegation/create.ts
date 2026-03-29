import { Serder } from '@kerizon/cesr';
import { DIP_FIELDS } from '../events/types.js';
import type { DelegatedInceptionConfig, DelegationSeal } from './types.js';

/**
 * Create a delegated inception event (dip).
 *
 * Builds the KED with `t: 'dip'` and `di` set to the delegator's AID,
 * then delegates to Serder.fromKed() for version string and SAID computation.
 */
export function createDelegatedInception(config: DelegatedInceptionConfig): Serder {
  const ked: Record<string, unknown> = {};

  for (const field of DIP_FIELDS) {
    switch (field) {
      case 'v': ked['v'] = ''; break;
      case 't': ked['t'] = 'dip'; break;
      case 'd': ked['d'] = ''; break;
      case 'i': ked['i'] = ''; break;
      case 's': ked['s'] = '0'; break;
      case 'kt': ked['kt'] = config.signingThreshold ?? '1'; break;
      case 'k': ked['k'] = config.keys; break;
      case 'nt': ked['nt'] = config.nextThreshold ?? '1'; break;
      case 'n': ked['n'] = config.nextDigests; break;
      case 'bt': ked['bt'] = (config.witnessThreshold ?? 0).toString(16); break;
      case 'b': ked['b'] = config.witnesses ?? []; break;
      case 'c': ked['c'] = config.configTraits ?? []; break;
      case 'a': ked['a'] = config.data ?? []; break;
      case 'di': ked['di'] = config.delegatorAid; break;
    }
  }

  return Serder.fromKed(ked);
}

/**
 * Create a delegation seal that anchors a delegate's event in the delegator's KEL.
 *
 * @param prefix  - the delegate's AID prefix
 * @param sn      - the delegate event sequence number
 * @param said    - the delegate event SAID
 */
export function createDelegationSeal(prefix: string, sn: number, said: string): DelegationSeal {
  return { i: prefix, s: sn.toString(16), d: said };
}
