import { Serder } from '@kerizon/cesr';
import type { ReplyConfig } from './types.js';

export function reply(config: ReplyConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    t: 'rpy', d: '', dt, r: config.route, a: config.data,
  };
  return Serder.fromKed(ked);
}
