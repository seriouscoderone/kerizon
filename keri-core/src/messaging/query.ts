import { Serder } from '@kerizon/cesr';
import type { QueryConfig } from './types.js';

export function query(config: QueryConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'qry', d: '', dt, r: config.route, rr: config.replyRoute, q: config.query,
  };
  return Serder.fromKed(ked);
}
