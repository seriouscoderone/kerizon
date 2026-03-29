import { Serder } from '@kerizon/cesr';
import type { CredentialState } from './types.js';

export interface CreateRegistryConfig {
  readonly issuerAid: string;
  readonly datetime?: string;
}

export interface CreateUpdateConfig {
  readonly registrySaid: string;
  readonly credentialSaid: string;
  readonly priorSaid: string;
  readonly sn: number;
  readonly targetState: CredentialState;
  readonly datetime?: string;
}

/**
 * Create a registry inception event (rip).
 *
 * The registry inception has i==d (self-addressing), similar to
 * KERI inception events where d==i. The Saider treats 'rip' as
 * an inception-like type, computing both d and i as the same SAID.
 */
export function createRegistry(config: CreateRegistryConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    v: '',
    t: 'rip',
    d: '',
    i: '',
    ii: config.issuerAid,
    n: '0',
    dt,
  };
  return Serder.fromKed(ked);
}

/**
 * Create a TEL update event (upd).
 *
 * Used for credential issuance (NotIssued -> Issued) and
 * revocation (Issued -> Revoked).
 */
export function createUpdate(config: CreateUpdateConfig): Serder {
  const dt = config.datetime ?? new Date().toISOString();
  const ked: Record<string, unknown> = {
    v: '',
    t: 'upd',
    d: '',
    rd: config.registrySaid,
    ta: config.credentialSaid,
    ts: config.targetState,
    n: config.sn.toString(16),
    p: config.priorSaid,
    dt,
  };
  return Serder.fromKed(ked);
}
