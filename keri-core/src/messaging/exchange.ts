import { Serder } from '@kerizon/cesr';
import type { ExchangeConfig } from './types.js';

export function exchange(config: ExchangeConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'exn', d: '', i: config.sender, rp: '',
    p: config.prior ?? '', dt, r: config.route,
    q: {}, a: config.payload, e: config.embeds ?? {},
  };
  return Serder.fromKed(ked);
}
