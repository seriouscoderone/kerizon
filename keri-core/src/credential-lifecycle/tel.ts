import type { Serder } from '@kerizon/cesr';
import type { CredentialState, CredentialStatus } from './types.js';
import { TEL_VALID_TRANSITIONS } from './types.js';

/**
 * TEL (Transaction Event Log) state machine.
 *
 * Tracks credential lifecycle states within a single registry.
 * Enforces valid transitions: NotIssued -> Issued -> Revoked.
 */
export class TelStateMachine {
  readonly registrySaid: string;
  private readonly states = new Map<string, CredentialStatus>();

  constructor(registrySaid: string) {
    this.registrySaid = registrySaid;
  }

  /**
   * Apply a TEL update event to the state machine.
   *
   * @throws if the transition is invalid
   */
  apply(serder: Serder): void {
    const ked = serder.ked;
    const credentialSaid = ked['ta'] as string;
    const targetState = ked['ts'] as CredentialState;
    const sn = parseInt(ked['n'] as string, 16);
    const dt = ked['dt'] as string | undefined;

    const current = this.getState(credentialSaid);
    const allowed = TEL_VALID_TRANSITIONS[current.state];

    if (!allowed.includes(targetState)) {
      throw new Error(
        `Invalid TEL transition: ${current.state} -> ${targetState} ` +
        `for credential ${credentialSaid}`,
      );
    }

    const updated: CredentialStatus = {
      state: targetState,
      credentialSaid,
      registrySaid: this.registrySaid,
      sn,
      issuedAt: targetState === 'Issued' ? dt : current.issuedAt,
      revokedAt: targetState === 'Revoked' ? dt : undefined,
    };

    this.states.set(credentialSaid, updated);
  }

  /**
   * Get the current state for a credential.
   *
   * Returns NotIssued with sn=0 for unknown credentials.
   */
  getState(credentialSaid: string): CredentialStatus {
    return this.states.get(credentialSaid) ?? {
      state: 'NotIssued',
      credentialSaid,
      registrySaid: this.registrySaid,
      sn: 0,
    };
  }
}
