import { describe, it, expect } from 'vitest';
import { TelStateMachine } from '../../src/credential-lifecycle/tel.js';
import { createRegistry, createUpdate } from '../../src/credential-lifecycle/registry.js';

describe('TelStateMachine', () => {
  const REG_SAID = 'ERegistrySaid_________________________________';
  const CRED_SAID = 'ECredentialSaid_______________________________';

  function makeIssuance(priorSaid: string) {
    return createUpdate({
      registrySaid: REG_SAID,
      credentialSaid: CRED_SAID,
      priorSaid,
      sn: 1,
      targetState: 'Issued',
    });
  }

  function makeRevocation(priorSaid: string) {
    return createUpdate({
      registrySaid: REG_SAID,
      credentialSaid: CRED_SAID,
      priorSaid,
      sn: 2,
      targetState: 'Revoked',
    });
  }

  it('transitions NotIssued -> Issued', () => {
    const tel = new TelStateMachine(REG_SAID);
    const issuance = makeIssuance('EPriorSaid____________________________________');
    tel.apply(issuance);

    const status = tel.getState(CRED_SAID);
    expect(status.state).toBe('Issued');
    expect(status.credentialSaid).toBe(CRED_SAID);
    expect(status.registrySaid).toBe(REG_SAID);
    expect(status.sn).toBe(1);
  });

  it('transitions Issued -> Revoked', () => {
    const tel = new TelStateMachine(REG_SAID);
    const issuance = makeIssuance('EPriorSaid____________________________________');
    tel.apply(issuance);

    const revocation = makeRevocation(issuance.said);
    tel.apply(revocation);

    const status = tel.getState(CRED_SAID);
    expect(status.state).toBe('Revoked');
    expect(status.sn).toBe(2);
  });

  it('rejects revocation before issuance', () => {
    const tel = new TelStateMachine(REG_SAID);
    const revocation = makeRevocation('EPriorSaid____________________________________');

    expect(() => tel.apply(revocation)).toThrow();
  });

  it('rejects double issuance', () => {
    const tel = new TelStateMachine(REG_SAID);
    const issuance1 = makeIssuance('EPriorSaid____________________________________');
    tel.apply(issuance1);

    const issuance2 = makeIssuance(issuance1.said);
    expect(() => tel.apply(issuance2)).toThrow();
  });

  it('unknown credential returns NotIssued state', () => {
    const tel = new TelStateMachine(REG_SAID);
    const status = tel.getState('EUnknownCred__________________________________');
    expect(status.state).toBe('NotIssued');
    expect(status.sn).toBe(0);
  });
});
